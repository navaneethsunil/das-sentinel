"""Deliberately-vulnerable sample for exercising the Semgrep adapter (M3-W2).

Contains classic Python SAST issues the vendored opengrep rule bundle flags. This
file is NEVER executed — it is scan fodder for the scanner framework's live proof
(scripts/verify_semgrep_scanner.py). It contains NO secret-shaped literals (which
would trip the Gitleaks block-on-any gate); every issue is a dangerous-API use.
"""

import hashlib
import os
import pickle
import subprocess


def run_user_command(cmd: str) -> None:
    # dangerous-subprocess-use: shell=True with an outside-controlled string.
    subprocess.run(cmd, shell=True, check=False)  # noqa
    # dangerous-system-call: os.system with an outside-controlled string.
    os.system(cmd)  # noqa


def evaluate(expression: str) -> object:
    # eval-detected: arbitrary code execution.
    return eval(expression)  # noqa


def weak_digest(data: bytes) -> str:
    # insecure-hash-algorithm-md5: MD5 for integrity.
    return hashlib.md5(data).hexdigest()  # noqa


def load_object(blob: bytes) -> object:
    # avoid-pickle: deserializing untrusted data.
    return pickle.loads(blob)  # noqa
