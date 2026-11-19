"""Shared test setup: makes scripts/scan.py importable as `scan`."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "device-checkup", "scripts")
SCAN_PY = os.path.join(SCRIPTS, "scan.py")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import scan  # noqa: E402,F401


def j(*parts):
    """Join string parts.

    Test inputs that look like malware command lines are assembled at runtime
    from pieces, so this repository's files never contain a complete malicious
    command. Antivirus engines scan files and command lines; a security tool's
    own test suite should not trip them.
    """
    return "".join(parts)
