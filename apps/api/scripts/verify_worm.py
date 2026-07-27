"""Pre-go-live WORM gate (CLAUDE.md §3): empirically prove the evidence store's
COMPLIANCE object-lock actually prevents deletion / mutation during retention.

The storage code SUPPORTS COMPLIANCE object-lock (S3EvidenceStore.put_object with
`retain_until`), but §3 requires this be EMPIRICALLY VERIFIED against a real
backend before evidence storage is "done" — chain-of-custody is a legal property,
not a code comment. This proves it against the configured S3-compatible backend
(dev: MinIO) using a throwaway object-lock bucket, so the main evidence bucket is
untouched:

  1. an object written with COMPLIANCE retention reports the lock;
  2. deleting that exact VERSION during retention is REJECTED — the WORM guarantee
     (a version-less delete only adds a delete-marker, so we target the version);
  3. the retained bytes are intact and the COMPLIANCE retention cannot be shortened
     (you can extend a COMPLIANCE lock, never weaken it — not even as owner);
  4. once retention expires the version becomes deletable (proving the block was
     retention-bounded, not a permanent artifact) — which also cleans up.

Backend-AGNOSTIC: this is the acceptance test ANY production WORM backend must pass.
Verified ALL PASS against dev MinIO AND against SeaweedFS (Apache-2.0, the chosen
production backend per the ROADMAP evidence-backend gate); the same script re-confirms
the gate against whatever a deployment runs (Ceph RGW, a commercial appliance, ...).
It reads the evidence-store settings, so target a backend by overriding MINIO_ENDPOINT
/ MINIO_SECURE / MINIO_ACCESS_KEY / MINIO_SECRET_KEY.

Run against the SeaweedFS profile (the verified production candidate):
  docker compose --profile seaweedfs up -d seaweedfs
  docker compose run --rm --no-deps \
    -e MINIO_ENDPOINT=seaweedfs:8333 -e MINIO_SECURE=false \
    -v "$PWD/apps/api/scripts:/app/scripts:ro" --entrypoint sh api \
    -c "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/verify_worm.py"
"""

import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.core.config import get_settings

_RETENTION_SECONDS = 5  # short window so the script can wait it out and clean up
_EVIDENCE = b"chain-of-custody evidence blob - do not lose"

failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        failures.append(name)


def _client(settings):  # noqa: ANN001, ANN202 - boto3 client, mirrors evidence.py
    scheme = "https" if settings.minio_secure else "http"
    return boto3.client(
        "s3",
        endpoint_url=f"{scheme}://{settings.minio_endpoint}",
        aws_access_key_id=settings.minio_access_key,
        aws_secret_access_key=settings.minio_secret_key.get_secret_value(),
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        use_ssl=settings.minio_secure,
    )


def _cleanup(client, bucket: str) -> None:  # noqa: ANN001 - best-effort teardown
    try:
        versions = client.list_object_versions(Bucket=bucket)
        for entry in [*versions.get("Versions", []), *versions.get("DeleteMarkers", [])]:
            try:
                client.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
            except ClientError:
                pass  # a still-locked version can't be removed — leave it
        client.delete_bucket(Bucket=bucket)
    except ClientError:
        pass


def main() -> int:
    settings = get_settings()
    client = _client(settings)
    bucket = f"worm-verify-{uuid.uuid4().hex[:12]}"
    key = "evidence/worm-probe"

    # An object-lock bucket can only be created WITH the flag — never enabled later.
    client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    try:
        retain_until = datetime.now(UTC) + timedelta(seconds=_RETENTION_SECONDS)
        put = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=_EVIDENCE,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
        )
        version_id = put.get("VersionId")
        check("wrote a COMPLIANCE-retained object (versioned)", bool(version_id))

        head = client.head_object(Bucket=bucket, Key=key, VersionId=version_id)
        check(
            "object reports COMPLIANCE mode + a retain-until date",
            head.get("ObjectLockMode") == "COMPLIANCE"
            and head.get("ObjectLockRetainUntilDate") is not None,
        )

        # THE WORM guarantee: the exact locked version cannot be deleted during
        # retention (a version-less delete only adds a delete-marker — not a test).
        try:
            client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
            check("locked version cannot be deleted during retention", False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            check(
                f"locked version cannot be deleted during retention (denied: {code})",
                code in ("AccessDenied", "InvalidRequest"),
            )

        # The retained bytes are intact and readable during retention.
        got = client.get_object(Bucket=bucket, Key=key, VersionId=version_id)["Body"].read()
        check("retained bytes are intact", got == _EVIDENCE)

        # COMPLIANCE retention cannot be SHORTENED (only extended) — not even by the
        # owner. A request to pull the date earlier must be refused.
        try:
            client.put_object_retention(
                Bucket=bucket,
                Key=key,
                VersionId=version_id,
                Retention={
                    "Mode": "COMPLIANCE",
                    "RetainUntilDate": datetime.now(UTC) + timedelta(seconds=1),
                },
            )
            check("COMPLIANCE retention cannot be shortened", False)
        except ClientError:
            check("COMPLIANCE retention cannot be shortened", True)

        # After retention expires the version is deletable — proving the block was
        # retention-bounded, not a permanent artifact.
        wait = (retain_until - datetime.now(UTC)).total_seconds() + 1.0
        if wait > 0:
            time.sleep(wait)
        try:
            client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
            check("after retention expiry the version can be deleted", True)
        except ClientError as exc:
            check(f"after retention expiry the version can be deleted ({exc})", False)
    finally:
        _cleanup(client, bucket)

    print(f"\n{'ALL PASS' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
