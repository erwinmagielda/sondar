"""
Sondar main entry point.

Temporary pre-flight runner used to test project paths, configuration loading,
and data directory preparation before the scanning workflow is added.
"""

import json
import sys

from utils.sondar_paths import (
    CONFIG_PATH,
    LOGS_DIR,
    REPORTS_DIR,
    SCANS_DIR,
    prepare_data_directories,
    relative_path,
)


# ------------------------------------------------------------
# CONFIG LOADING
# ------------------------------------------------------------

def load_config() -> dict:
    """Load Sondar configuration from config/sondar_config.json."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Configuration file missing: {relative_path(CONFIG_PATH)}"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the temporary Sondar pre-flight workflow."""
    print()
    print("=" * 60)
    print("Sondar - Pre-flight")
    print("=" * 60)
    print()

    try:
        print("--- Paths ---")
        print("[*] Preparing data directories")
        prepare_data_directories()
        print(f"[+] Scans directory ready: {relative_path(SCANS_DIR)}")
        print(f"[+] Reports directory ready: {relative_path(REPORTS_DIR)}")
        print(f"[+] Logs directory ready: {relative_path(LOGS_DIR)}")
        print()

        print("--- Configuration ---")
        print("[*] Loading configuration")
        config = load_config()
        print(f"[+] Configuration loaded: {relative_path(CONFIG_PATH)}")

        project_name = config.get("project_name", "Sondar")
        version = config.get("version", "0.1.0")
        scan_config = config.get("scan", {})

        print(f"[i] Project: {project_name}")
        print(f"[i] Version: {version}")
        print(f"[i] Fallback Target: {scan_config.get('fallback_target', 'Not configured')}")
        print(f"[i] Scan Mode: {scan_config.get('scan_mode', 'Not configured')}")
        print()

        print("[+] Pre-flight completed")
        return 0

    except Exception as error:
        print()
        print("[X] Pre-flight failed")
        print(f"[X] {error}")
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())