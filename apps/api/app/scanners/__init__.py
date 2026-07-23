"""Scanner adapters (M3). Each wraps one external tool behind the uniform
`ScannerAdapter` contract (base.py); the framework (workers/scanner_run.py) owns
execution through the killable, confined execution owner."""

from app.scanners.base import (
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
from app.scanners.stub import StubScanner

__all__ = [
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
    "StubScanner",
    "serialize_scanner_result",
]
