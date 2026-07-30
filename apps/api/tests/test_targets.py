"""M1-B10: auth_config references-only enforcement (TR-23). Endpoint CRUD +
org scoping is verified live (scripts/verify_targets.py); here we pin the pure
validator that keeps plaintext secrets out of auth_config."""

import pytest

from app.services.targets import validate_auth_config_references


@pytest.mark.parametrize(
    "config",
    [
        None,
        {},
        {"secret_ref": "vault://kv/acme/web"},
        {"api_key_id": "akid-123"},
        {"credential_uri": "gsm://projects/p/secrets/s"},
        {"token_arn": "arn:aws:secretsmanager:...:secret:tok"},
        {"username": "svc-scanner"},  # username is not a secret
        {"auth": {"password_ref": "vault://kv/acme/pw"}},  # nested reference
        {"headers": [{"name": "X-Api", "value_ref": "vault://..."}]},  # list of refs
        {"api_key_ref": "cred:123e4567-e89b-12d3-a456-426614174000"},  # managed credential
        {"api_key_ref": "env:MY_TARGET_KEY"},  # env reference
    ],
)
def test_reference_configs_accepted(config: dict | None) -> None:
    validate_auth_config_references(config)  # must not raise


@pytest.mark.parametrize(
    "config",
    [
        {"password": "hunter2"},
        {"api_key": "sk-live-abc"},
        {"secret": "s3cr3t"},
        {"token": "ghp_xxx"},
        {"private_key": "-----BEGIN..."},
        {"key": "raw"},
        {"pwd": "raw"},
        {"auth": {"password": "nested-plaintext"}},  # nested secret caught
        {"headers": [{"authorization_token": "Bearer xyz"}]},  # inside a list
    ],
)
def test_plaintext_secret_configs_rejected(config: dict) -> None:
    with pytest.raises(ValueError, match="plaintext secret"):
        validate_auth_config_references(config)


@pytest.mark.parametrize(
    "config",
    [
        {"api_key_ref": "hunter2"},  # plaintext hiding under a reference-shaped key
        {"auth": {"token_ref": "ghp_rawtoken"}},  # nested plaintext under _ref
        {"headers": [{"value_ref": "Bearer raw-secret"}]},  # inside a list
    ],
)
def test_plaintext_value_under_ref_key_rejected(config: dict) -> None:
    # The value-level gate: a *_ref key must carry a recognized reference scheme
    # (cred:/env:/vault:), never a raw secret.
    with pytest.raises(ValueError, match="credential reference"):
        validate_auth_config_references(config)
