"""M0-D1: migration scaffold sanity — single linear head rooted at the baseline."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))


def test_single_head() -> None:
    # Two heads means a fork someone forgot to merge — `alembic upgrade head` would fail.
    heads = script_directory().get_heads()
    assert len(heads) == 1


def test_history_roots_at_empty_baseline() -> None:
    script = script_directory()
    revisions = list(script.walk_revisions())
    root = revisions[-1]
    assert root.down_revision is None
    assert "baseline" in (root.doc or "")
