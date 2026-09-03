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


# ── sec-2: proxy-IP trust so the login limiter keys on the real client ────────


def _proxy_static_ip() -> str:
    proxy_net = compose_services()["proxy"]["networks"]["internal"]
    return proxy_net["ipv4_address"]


def test_api_trusts_exactly_the_pinned_proxy_ip():
    """The API's FORWARDED_ALLOW_IPS must equal the proxy's STATIC address and
    never '*' — otherwise Uvicorn ignores X-Forwarded-For (every external client
    collapses onto the proxy's bridge IP in the login limiter, sec-2) or trusts
    everyone (spoofable)."""
    api_env = compose_services()["api"].get("environment", {})
    allow = api_env.get("FORWARDED_ALLOW_IPS")
    assert allow, "api service must set FORWARDED_ALLOW_IPS"
    assert allow != "*", "FORWARDED_ALLOW_IPS must never be '*' (spoofable)"
    assert allow == _proxy_static_ip(), (
        f"FORWARDED_ALLOW_IPS ({allow!r}) must equal the proxy's static IP ({_proxy_static_ip()!r})"
    )


def test_proxy_headers_resolve_client_from_trusted_proxy_only():
    """Behavioral proof at the exact deployed trust value: Uvicorn honors
    X-Forwarded-For only when the connecting peer IS the trusted proxy; a forged
    header from any other peer is ignored (the peer's real IP wins)."""
    import asyncio

    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    trusted_ip = _proxy_static_ip()

    async def resolve_client(peer_ip: str, forwarded_for: str) -> str:
        captured: dict[str, object] = {}

        async def inner(scope, receive, send):
            captured["client"] = scope.get("client")

        mw = ProxyHeadersMiddleware(inner, trusted_hosts=trusted_ip)
        scope = {
            "type": "http",
            "client": (peer_ip, 12345),
            "headers": [(b"x-forwarded-for", forwarded_for.encode())],
        }
        await mw(scope, None, None)
        client = captured["client"]
        assert client is not None
        return client[0]

    async def main() -> None:
        # From the trusted proxy: the forwarded client IP is used.
        assert await resolve_client(trusted_ip, "203.0.113.7") == "203.0.113.7"
        # From any other peer: the forged header is ignored.
        assert await resolve_client("172.28.0.99", "203.0.113.7") == "172.28.0.99"

    asyncio.run(main())


# ── sec-5: no default ZAP key, control API locked to the scanner-worker ───────


def _zap_command() -> list[str]:
    return compose_services()["zap"]["command"]


def test_zap_command_has_no_baked_in_default_key():
    """The compose file must not substitute a known-weak key into the ZAP
    daemon (sec-5). A real key comes from ZAP_API_KEY in .env; unset resolves to
    empty, and the adapter refuses to scan on an empty/weak key."""
    cmd = _zap_command()
    key_arg = next((a for a in cmd if a.startswith("api.key=")), None)
    assert key_arg is not None, "zap command must set api.key"
    assert "change-me" not in key_arg and "changeme" not in key_arg, (
        f"zap api.key carries a known-weak default: {key_arg!r}"
    )
    assert key_arg in ("api.key=${ZAP_API_KEY:-}", "api.key=${ZAP_API_KEY}"), (
        f"unexpected zap api.key form: {key_arg!r}"
    )


def test_zap_api_callers_restricted_to_internal_control_network():
    """ZAP's api.addrs allowlist must NOT be a wildcard: it permits the internal
    control subnet, loopback (healthcheck), and the `zap` host header the worker
    uses, but not the `targets` labs subnet (172.18.x) — a popped lab must not
    reach the control API even though the daemon is dual-homed (sec-5)."""
    import re

    cmd = _zap_command()
    name = next((a.split("=", 1)[1] for a in cmd if a.startswith("api.addrs.addr.name=")), None)
    regex = next((a.split("=", 1)[1] for a in cmd if a.startswith("api.addrs.addr.regex=")), None)
    assert name and name not in (".*", "*"), "ZAP api.addrs must not be a wildcard"
    assert regex == "true", "expected a regex allowlist"

    pattern = re.compile(name)
    worker_ip = compose_services()["scanner-worker"]["networks"]["internal"]["ipv4_address"]
    # Allowed: the scanner-worker (internal), loopback (healthcheck), the `zap` host.
    assert pattern.fullmatch(worker_ip), f"{worker_ip} (scanner-worker) must be permitted"
    assert pattern.fullmatch("127.0.0.1"), "loopback (healthcheck) must be permitted"
    assert pattern.fullmatch("zap"), "the `zap` host header must be permitted"
    # Denied: any address on the shared targets network (the popped-lab threat).
    assert not pattern.fullmatch("172.18.0.4"), "targets-network labs must be denied"
