"""
Sondar scan execution.

Runs controlled nmap scans against an operator-confirmed target and writes raw
XML output to data/scans for later parsing.
"""

import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from utils.sondar_paths import SCANS_DIR, relative_path


# ------------------------------------------------------------
# NMAP CHECKS
# ------------------------------------------------------------

def check_nmap_available() -> str:
    """
    Return the nmap executable path if nmap is available.

    Raises RuntimeError when nmap cannot be found in PATH.
    """
    nmap_path = shutil.which("nmap")

    if not nmap_path:
        raise RuntimeError(
            "nmap was not found in PATH. Install nmap or add it to PATH."
        )

    return nmap_path


# ------------------------------------------------------------
# COMMAND BUILDING
# ------------------------------------------------------------

def build_scan_command(target: str, scan_mode: str, output_path: Path) -> list[str]:
    """
    Build an nmap command for the selected scan mode.

    The initial basic mode uses common TCP port service detection and XML output.
    """
    if scan_mode != "basic":
        raise ValueError(f"Unsupported scan mode: {scan_mode}")

    return [
        "nmap",
        "-sV",
        "--top-ports",
        "100",
        "-oX",
        str(output_path),
        target,
    ]


# ------------------------------------------------------------
# SCAN EXECUTION
# ------------------------------------------------------------

def run_scan(target: str, scan_mode: str, timeout_seconds: int) -> dict[str, str | int]:
    """
    Run an nmap scan and return scan metadata.

    Raw XML output is written to data/scans.
    """
    check_nmap_available()
    SCANS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = SCANS_DIR / f"sondar_scan_{timestamp}.xml"

    command = build_scan_command(target, scan_mode, output_path)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"nmap scan failed with exit code {result.returncode}: "
            f"{result.stderr.strip()}"
        )

    return {
        "target": target,
        "scan_mode": scan_mode,
        "output_path": relative_path(output_path),
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }