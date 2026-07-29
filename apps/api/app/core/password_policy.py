"""Breached / common-password rejection at set-time (SEC-DEBT-3).

Air-gap-first: no HIBP online egress. A newline-delimited corpus of known-breached
/ common passwords is loaded into a set and checked for membership (case-folded).
A small curated starter list ships in `data/common_breached_passwords.txt`; point
`BREACHED_PASSWORD_LIST_PATH` at a full offline corpus (e.g. a SecLists rockyou
file mounted into the image) in production.

ponytail: in-memory set — fine to a few million entries. For a very large corpus,
swap the set for a bloom filter or an on-disk SHA-1-prefix index (HIBP offline).
"""

import functools
from pathlib import Path

_DEFAULT_CORPUS = Path(__file__).parent / "data" / "common_breached_passwords.txt"


class PasswordBreachChecker:
    def __init__(self, corpus_path: str | None = None) -> None:
        path = Path(corpus_path) if corpus_path else _DEFAULT_CORPUS
        self._breached = self._load(path)

    @staticmethod
    def _load(path: Path) -> frozenset[str]:
        if not path.exists():
            return frozenset()
        return frozenset(
            stripped.casefold()
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if (stripped := line.strip()) and not stripped.startswith("#")
        )

    @property
    def size(self) -> int:
        return len(self._breached)

    def is_breached(self, password: str) -> bool:
        """True if the password (case-folded) is in the corpus. Empty corpus →
        always False: the length floor + Argon2id still apply, and a missing
        corpus must not block every password (that would be a set-time DoS)."""
        return password.casefold() in self._breached


@functools.lru_cache(maxsize=4)
def get_breach_checker(corpus_path: str | None) -> PasswordBreachChecker:
    """Cache per corpus path so the file is read once, not per request."""
    return PasswordBreachChecker(corpus_path)
