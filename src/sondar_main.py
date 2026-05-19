"""
Sondar main entry point.

Temporary pre-flight runner used to test project paths, configuration loading,
logging, local target detection, and data directory preparation before the
scanning workflow is added.
"""

import json
import sys
import ipaddress

from core.sondar_network import get_primary_target
from core.sondar_scanner import run_scan

from utils.sondar_banner import print_main_header, print_section, print_status
from utils.sondar_logger import setup_logger
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
# TARGET SELECTION
# ------------------------------------------------------------

def detect_scan_target(scan_config: dict, logger) -> dict[str, str]:
    """
    Detect the preferred scan target using local interface data.

    Falls back to the configured fallback target when local detection fails or
    auto-detection is disabled.
    """
    fallback_target = scan_config.get("fallback_target", "192.168.1.0/24")
    auto_detect = scan_config.get("auto_detect_target", True)

    if not auto_detect:
        logger.info("Target auto-detection disabled")
        return {
            "source": "fallback",
            "adapter": "Auto-detection disabled",
            "ipv4_address": "Not detected",
            "subnet_mask": "Not detected",
            "cidr_target": fallback_target,
        }

    try:
        return get_primary_target(fallback_target)
    except Exception as error:
        logger.warning("Target auto-detection failed: %s", error)
        return {
            "source": "fallback",
            "adapter": "Detection failed",
            "ipv4_address": "Not detected",
            "subnet_mask": "Not detected",
            "cidr_target": fallback_target,
        }


# ------------------------------------------------------------
# TARGET CONFIRMATION
# ------------------------------------------------------------

def is_valid_cidr(target: str) -> bool:
    """Return True if the provided target is a valid IPv4 CIDR network."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False

    return network.version == 4


def confirm_scan_target(target_details: dict[str, str], scan_config: dict, logger) -> str:
    """
    Confirm the detected scan target with the operator.

    If confirmation is disabled, the suggested target is returned directly.
    """
    suggested_target = target_details["cidr_target"]
    confirm_target = scan_config.get("confirm_target_before_scan", True)

    if not confirm_target:
        logger.info("Target confirmation disabled")
        return suggested_target

    response = input(f"Confirm target {suggested_target}? [Y/n]: ").strip().lower()

    if response in ("", "y", "yes"):
        logger.info("Target confirmed: %s", suggested_target)
        return suggested_target

    while True:
        manual_target = input("Enter scan target manually: ").strip()

        if is_valid_cidr(manual_target):
            logger.info("Manual target selected: %s", manual_target)
            return manual_target

        print_status("!", "Invalid CIDR target. Example: 192.168.1.0/24")


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the temporary Sondar pre-flight workflow."""
    print_main_header("Sondar - Pre-flight")

    try:
        print_section("Paths")
        print_status("*", "Preparing data directories")
        prepare_data_directories()
        print_status("+", f"Scans directory ready: {relative_path(SCANS_DIR)}")
        print_status("+", f"Reports directory ready: {relative_path(REPORTS_DIR)}")
        print_status("+", f"Logs directory ready: {relative_path(LOGS_DIR)}")
        print()

        print_status("*", "Initialising logger")
        logger, log_path = setup_logger()
        print_status("+", f"Logger ready: {relative_path(log_path)}")
        print()

        print_section("Configuration")
        print_status("*", "Loading configuration")
        config = load_config()
        print_status("+", f"Configuration loaded: {relative_path(CONFIG_PATH)}")

        project_name = config.get("project_name", "Sondar")
        version = config.get("version", "0.1.0")
        scan_config = config.get("scan", {})

        logger.info("Configuration loaded: %s", relative_path(CONFIG_PATH))
        logger.info("Project: %s", project_name)
        logger.info("Version: %s", version)
        logger.info(
            "Fallback target: %s",
            scan_config.get("fallback_target", "Not configured")
        )
        logger.info(
            "Scan mode: %s",
            scan_config.get("scan_mode", "Not configured")
        )

        print_status("i", f"Project: {project_name}")
        print_status("i", f"Version: {version}")
        print_status(
            "i",
            f"Fallback Target: {scan_config.get('fallback_target', 'Not configured')}"
        )
        print_status(
            "i",
            f"Scan Mode: {scan_config.get('scan_mode', 'Not configured')}"
        )
        print()

        print_section("Target Selection")
        print_status("*", "Detecting local network target")
        target_details = detect_scan_target(scan_config, logger)

        logger.info("Target source: %s", target_details["source"])
        logger.info("Adapter: %s", target_details["adapter"])
        logger.info("IPv4 address: %s", target_details["ipv4_address"])
        logger.info("Subnet mask: %s", target_details["subnet_mask"])
        logger.info("Selected target: %s", target_details["cidr_target"])

        print_status("+", f"Target source: {target_details['source']}")
        print_status("i", f"Adapter: {target_details['adapter']}")
        print_status("i", f"IPv4 Address: {target_details['ipv4_address']}")
        print_status("i", f"Subnet Mask: {target_details['subnet_mask']}")
        print_status("+", f"Suggested Target: {target_details['cidr_target']}")
        
        selected_target = confirm_scan_target(target_details, scan_config, logger)
        print_status("+", f"Selected Target: {selected_target}")
        logger.info("Confirmed scan target: %s", selected_target)
        print()

        print_section("Scan Execution")
        print_status("*", "Running basic network scan")

        scan_mode = scan_config.get("scan_mode", "basic")
        timeout_seconds = scan_config.get("timeout_seconds", 120)

        scan_result = run_scan(selected_target, scan_mode, timeout_seconds)

        logger.info("Scan completed")
        logger.info("Scan output: %s", scan_result["output_path"])

        print_status("+", "Scan completed")
        print_status("+", f"Raw scan saved: {scan_result['output_path']}")
        print()

        print_status("+", "Pre-flight completed")
        return 0

    except Exception as error:
        print()
        print_status("X", "Pre-flight failed")
        print_status("X", str(error))
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())