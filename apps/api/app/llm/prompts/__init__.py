"""Versioned prompt templates (M2-B2, CLAUDE.md §7: templates live in files, not
inline strings). Each template is a file named `<name>.v<N>.txt` in this
directory; the version is part of the filename so a prompt change is a new file,
never an in-place edit — and the exact template id is recorded on every
`llm_interactions` row for audit reproducibility.
"""

import re
from dataclasses import dataclass
from pathlib import Path

_PROMPT_DIR = Path(__file__).parent
_FILENAME = re.compile(r"^(?P<name>[a-z0-9_]+)\.v(?P<version>\d+)\.txt$")


class PromptNotFoundError(Exception):
    """No template file matches the requested name/version."""


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    version: int
    body: str

    @property
    def template_id(self) -> str:
        """Stamped into `llm_interactions.prompt_template` for audit."""
        return f"{self.name}@v{self.version}"

    def render(self, **values: object) -> str:
        return self.body.format(**values)


def _discover() -> dict[tuple[str, int], Path]:
    found: dict[tuple[str, int], Path] = {}
    for path in _PROMPT_DIR.glob("*.txt"):
        match = _FILENAME.match(path.name)
        if match:
            found[(match["name"], int(match["version"]))] = path
    return found


def load_prompt(name: str, version: int | None = None) -> PromptTemplate:
    """Load a template by name. With no version, the highest available is used."""
    templates = _discover()
    versions = sorted(v for (n, v) in templates if n == name)
    if not versions:
        raise PromptNotFoundError(name)
    chosen = version if version is not None else versions[-1]
    if (name, chosen) not in templates:
        raise PromptNotFoundError(f"{name}@v{chosen}")
    body = templates[(name, chosen)].read_text(encoding="utf-8")
    return PromptTemplate(name=name, version=chosen, body=body)
