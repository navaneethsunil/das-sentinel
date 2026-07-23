"""Scanner adapters (M3). Each wraps one external tool behind the uniform
`ScannerAdapter` contract (base.py); the framework (workers/scanner_run.py) owns
execution through the killable, confined execution owner."""

from app.scanners.base import (
    ApiScannerAdapter,
    NormalizedFinding,
    OutputMode,
    RawScannerResult,
    ScannerAdapter,
    ScannerConfig,
    ScannerError,
    ScannerInvocation,
    ScannerPrerequisiteError,
    ScannerResult,
    ScannerTarget,
    serialize_scanner_result,
)
from app.scanners.semgrep import SemgrepScanner
from app.scanners.stub import StubScanner
from app.scanners.zap import ZapScanner

__all__ = [
    "ApiScannerAdapter",
    "NormalizedFinding",
    "OutputMode",
    "RawScannerResult",
    "ScannerAdapter",
    "ScannerConfig",
    "ScannerError",
    "ScannerInvocation",
    "ScannerPrerequisiteError",
    "ScannerResult",
    "ScannerTarget",
    "SemgrepScanner",
    "StubScanner",
    "ZapScanner",
    "serialize_scanner_result",
]
