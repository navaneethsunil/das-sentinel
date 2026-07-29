"""PasswordBreachChecker unit tests (SEC-DEBT-3). The HTTP 422 wiring on
create/change is live-verified in scripts/verify_password_breach.py."""

from pathlib import Path

from app.core.password_policy import PasswordBreachChecker, get_breach_checker


def _checker(tmp_path: Path, lines: list[str]) -> PasswordBreachChecker:
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return PasswordBreachChecker(str(corpus))


def test_bundled_corpus_loads_and_flags_common_passwords():
    checker = PasswordBreachChecker()  # ships with the app
    assert checker.size > 50
    assert checker.is_breached("password")
    assert checker.is_breached("passwordpassword")
    assert not checker.is_breached("Zt9!mq-Vx2_Lp7wRa3")  # random strong


def test_match_is_case_insensitive(tmp_path: Path):
    checker = _checker(tmp_path, ["passwordpassword"])
    assert checker.is_breached("PasswordPassword")
    assert checker.is_breached("PASSWORDPASSWORD")


def test_comments_and_blanks_ignored(tmp_path: Path):
    checker = _checker(tmp_path, ["# header", "", "  ", "letmein123456", "# trailing"])
    assert checker.size == 1
    assert checker.is_breached("letmein123456")


def test_missing_corpus_flags_nothing(tmp_path: Path):
    # A missing corpus must not block every password (set-time DoS); length +
    # Argon2id remain the floor.
    checker = PasswordBreachChecker(str(tmp_path / "does-not-exist.txt"))
    assert checker.size == 0
    assert not checker.is_breached("password")


def test_checker_is_cached_per_path(tmp_path: Path):
    corpus = tmp_path / "c.txt"
    corpus.write_text("password\n", encoding="utf-8")
    a = get_breach_checker(str(corpus))
    b = get_breach_checker(str(corpus))
    assert a is b  # same path → one load, not per request
