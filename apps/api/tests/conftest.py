"""Shared fixtures: tests run against the repo-root `.env.example` values, so
the template is proven loadable and can't drift from Settings' required fields.
"""

from pathlib import Path

import pytest

ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"


def example_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env[key] = value
    return env


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = example_env()
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values
