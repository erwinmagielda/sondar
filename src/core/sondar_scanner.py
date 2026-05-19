"""
Sondar scan execution.

Runs controlled nmap scans against an operator-confirmed target and writes raw
XML output to data/scans for later parsing.
"""

import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from utils.sondar_paths import SCANS_DIR, relative_path


# ------------------------------------------------------------
# SCAN PROFILES
# ------------------------------------------------------------

SUPPORTED_SCAN_MODES = {
    "discovery",
    "basic",
    "standard",
    "deep",
}


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

def build_discovery_command(target: str, output_path: Path) -> list[str]:
    """Build a host-discovery-only nmap command."""
    return [
        "nmap",
        "-sn",
        "-oX",
        str(output_path),
        target,
    ]


def build_basic_command(target: str, output_path: Path) -> list[str]:
    """Build a fast service scan using the top 100 TCP ports."""
    return [
        "nmap",
        "-sV",
        "--top-ports",
        "100",
        "-oX",
        str(output_path),
        target,
    ]


def build_standard_command(target: str, output_path: Path) -> list[str]:
    """Build a broader service scan using the top 1000 TCP ports."""
    return [
        "nmap",
        "-sV",
        "--top-ports",
        "1000",
        "-oX",
        str(output_path),
        target,
    ]


def build_deep_command(target: str, output_path: Path) -> list[str]:
    """Build a full TCP port range service scan."""
    return [
        "nmap",
        "-sV",
        "-p-",
        "-oX",
        str(output_path),
        target,
    ]


def build_scan_command(target: str, scan_mode: str, output_path: Path) -> list[str]:
    """
    Build an nmap command for the selected scan mode.
    """
    if scan_mode not in SUPPORTED_SCAN_MODES:
        supported_modes = ", ".join(sorted(SUPPORTED_SCAN_MODES))
        raise ValueError(
            f"Unsupported scan mode: {scan_mode}. "
            f"Supported modes: {supported_modes}"
        )

    if scan_mode == "discovery":
        return build_discovery_command(target, output_path)

    if scan_mode == "basic":
        return build_basic_command(target, output_path)

    if scan_mode == "standard":
        return build_standard_command(target, output_path)

    if scan_mode == "deep":
        return build_deep_command(target, output_path)

    raise ValueError(f"Unsupported scan mode: {scan_mode}")


# ------------------------------------------------------------
# SCAN EXECUTION
# ------------------------------------------------------------

def run_scan(target: str, scan_mode: str, timeout_seconds: int) -> dict[str, Any]:
    """
    Run an nmap scan and return scan metadata.

    Raw XML output is written to data/scans.
    """
    check_nmap_available()
    SCANS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = SCANS_DIR / f"sondar_scan_{scan_mode}_{timestamp}.xml"

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
        "command": " ".join(command),
        "output_path": relative_path(output_path),
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }