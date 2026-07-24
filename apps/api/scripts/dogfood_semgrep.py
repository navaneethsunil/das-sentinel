"""M3-SEC3 dogfood: normalize DAS Sentinel's OWN Semgrep scan output through our
OWN Semgrep adapter (SECURITY_DEVELOPMENT_PLAN §4).

CI runs Semgrep over `apps/ packages/ sandbox/` and writes `semgrep.json`. This
script feeds that real output through `SemgrepScanner.normalize` — the exact
adapter we ship — and prints a triage summary, proving our adapter turns our own
codebase's scan output into structured findings. "If our own Semgrep integration
can't find issues in our own code, it isn't good enough to ship."

Usage: python scripts/dogfood_semgrep.py <path-to-semgrep.json>
Exits non-zero if the adapter yields no normalized findings (the dogfood failed)
or the input is unusable.
"""

import sys
from collections import Counter
from pathlib import Path

from app.scanners.base import RawScannerResult
from app.scanners.semgrep import SemgrepScanner

# The intentional-vuln SAST fixture (M3-W2 scan fodder). Findings here are
# expected; the dogfood is more meaningful for findings OUTSIDE it (real code).
_FIXTURE_PREFIX = "sandbox/vulnerable_sample/"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: dogfood_semgrep.py <semgrep.json>", file=sys.stderr)
        return 2
    raw_path = Path(sys.argv[1])
    if not raw_path.is_file():
        print(f"semgrep output not found: {raw_path}", file=sys.stderr)
        return 2

    output = raw_path.read_bytes()
    # Drive the SHIPPED adapter's normalizer over our own scan output.
    findings = SemgrepScanner(binary="semgrep").normalize(
        RawScannerResult(exit_code=1, output=output, stderr=b"")
    )

    by_severity: Counter[str] = Counter(f.severity.value for f in findings)
    fixture = [f for f in findings if str(f.location.get("file") or "").startswith(_FIXTURE_PREFIX)]
    real_code = [f for f in findings if f not in fixture]

    print(f"Semgrep adapter dogfood: normalized {len(findings)} finding(s) from our own scan")
    print(f"  by severity: {dict(by_severity)}")
    print(f"  in intentional-vuln fixture: {len(fixture)} | elsewhere: {len(real_code)}")
    for f in findings[:10]:
        loc = f.location.get("file")
        line = f.location.get("start_line")
        print(f"  - [{f.severity.value}] {f.rule_id} {loc}:{line}")

    if not findings:
        print(
            "DOGFOOD FAILED: our Semgrep adapter produced no normalized findings "
            "from our own codebase's scan output.",
            file=sys.stderr,
        )
        return 1
    print("DOGFOOD OK: our Semgrep adapter produced normalized findings from our own code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
