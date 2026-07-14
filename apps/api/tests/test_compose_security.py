"""M0-SEC2 security gate (TM-12, TM-5), pinned as tests so it can't regress:

- every compose service declares deploy.resources.limits (a runaway scan must
  not starve the DB) and the worker runs under --init (zombie reaping / signal
  forwarding for scanner subprocesses — CLAUDE.md §6a)
- only the proxy publishes a host port (single ingress, TR-4); dev-profile
  exceptions must stay loopback-bound
- .gitignore keeps secret paths out of the repo and .env.example carries
  placeholders only (TR-23)
"""

import subprocess
from pathlib import Path

import yaml

from tests.conftest import ENV_EXAMPLE, example_env

REPO_ROOT = Path(__file__).resolve().parents[3]

# A key names a secret when its FINAL token is the marker (POSTGRES_PASSWORD,
# MINIO_SECRET_KEY, ANTHROPIC_API_KEY) — not when the marker merely appears
# (PASSWORD_HASH_SCHEME is config *about* passwords, not a credential).
SECRET_KEY_MARKERS = ("PASSWORD", "SECRET", "TOKEN", "KEY")
PLACEHOLDER_VALUES = {"", "change-me"}


def compose_services() -> dict:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    return compose["services"]


def test_every_service_declares_resource_limits():
    for name, service in compose_services().items():
        limits = service.get("deploy", {}).get("resources", {}).get("limits", {})
        assert limits.get("cpus"), f"service {name!r} missing deploy.resources.limits.cpus"
        assert limits.get("memory"), f"service {name!r} missing deploy.resources.limits.memory"


def test_worker_runs_under_init():
    assert compose_services()["worker"].get("init") is True


def test_only_proxy_publishes_host_ports():
    for name, service in compose_services().items():
        ports = service.get("ports", [])
        if name == "proxy":
            assert ports, "proxy must publish the single ingress port"
            continue
        for port in ports:
            assert "dev" in service.get("profiles", []) and str(port).startswith("127.0.0.1:"), (
                f"service {name!r} publishes host port {port!r} — only proxy may (TR-4); "
                "dev-profile exceptions must bind loopback"
            )


def git_check_ignore(path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", path],
        check=False,
    )
    assert result.returncode in (0, 1), f"git check-ignore errored for {path!r}"
    return result.returncode == 0


def test_gitignore_excludes_secret_paths():
    for path in (".env", ".env.local", ".env.production", "secrets/creds.json", "a.pem", "a.key"):
        assert git_check_ignore(path), f"{path!r} is not gitignored"


def test_env_example_is_tracked_not_ignored():
    assert not git_check_ignore(".env.example")


def test_env_example_holds_placeholders_only():
    for key, value in example_env().items():
        if key.rsplit("_", 1)[-1] in SECRET_KEY_MARKERS:
            assert value in PLACEHOLDER_VALUES, (
                f"{key} in {ENV_EXAMPLE.name} looks like a real credential "
                f"(value {value!r}); placeholders only (TR-23)"
            )
