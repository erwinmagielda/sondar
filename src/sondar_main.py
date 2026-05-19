"""
Sondar main entry point.

Workflow runner for network scanning, target confirmation, per-run scan mode
selection, XML parsing, inventory creation, change detection, report generation,
menu operation, and runtime artefact clearing.
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path

from core.sondar_artefacts import clear_runtime_artefacts, count_removed_files
from core.sondar_detector import detect_inventory_changes
from core.sondar_inventory import save_inventory_snapshot
from core.sondar_network import get_primary_target
from core.sondar_parser import parse_nmap_xml
from core.sondar_reporter import save_markdown_report
from core.sondar_scanner import run_scan
from utils.sondar_banner import print_main_header, print_section, print_status
from utils.sondar_logger import setup_logger
from utils.sondar_paths import (
    CONFIG_PATH,
    INVENTORY_DIR,
    LOGS_DIR,
    REPORTS_DIR,
    SCANS_DIR,
    prepare_data_directories,
    relative_path,
)


# ------------------------------------------------------------
# ARGUMENT PARSING
# ------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Parse Sondar command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Sondar home network scanning workflow"
    )

    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run the network scan workflow directly",
    )

    parser.add_argument(
        "--clear-artefacts",
        action="store_true",
        help="Clear generated runtime artefacts and exit",
    )

    return parser.parse_args()


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
    fallback_target = scan_config.get("fallback_target", "").strip()
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


def prompt_for_manual_target(logger) -> str:
    """Prompt the operator until a valid IPv4 CIDR target is entered."""
    while True:
        manual_target = input("Enter scan target manually: ").strip()

        if is_valid_cidr(manual_target):
            logger.info("Manual target selected: %s", manual_target)
            return manual_target

        print_status("!", "Invalid CIDR target. Example: 192.168.1.0/24")


def confirm_scan_target(
    target_details: dict[str, str],
    scan_config: dict,
    logger,
) -> str:
    """
    Confirm the detected scan target with the operator.

    If no usable target is detected, prompt the operator for a manual CIDR
    target when manual entry is allowed.
    """
    suggested_target = target_details.get("cidr_target", "").strip()
    confirm_target = scan_config.get("confirm_target_before_scan", True)
    allow_manual_target = scan_config.get("allow_manual_target", True)

    if not suggested_target:
        if not allow_manual_target:
            raise RuntimeError(
                "No scan target detected and manual target entry is disabled"
            )

        print_status("!", "No scan target was auto-detected")
        return prompt_for_manual_target(logger)

    if not confirm_target:
        logger.info("Target confirmation disabled")
        return suggested_target

    response = input(f"Confirm target {suggested_target}? [Y/n]: ").strip().lower()

    if response in ("", "y", "yes"):
        logger.info("Target confirmed: %s", suggested_target)
        return suggested_target

    if not allow_manual_target:
        raise RuntimeError("Detected target rejected and manual target entry is disabled")

    return prompt_for_manual_target(logger)


# ------------------------------------------------------------
# SCAN MODE SELECTION
# ------------------------------------------------------------

SCAN_MODE_OPTIONS = {
    "1": "discovery",
    "2": "basic",
    "3": "standard",
    "4": "deep",
}


def get_scan_mode_option_number(scan_mode: str) -> str:
    """Return the menu option number for a scan mode."""
    for option, mode in SCAN_MODE_OPTIONS.items():
        if mode == scan_mode:
            return option

    return "2"


def select_scan_mode_for_run(scan_config: dict) -> str:
    """
    Let the operator select a scan mode for the current run.

    This does not modify config/sondar_config.json.
    """
    default_mode = scan_config.get("scan_mode", "basic")
    default_option = get_scan_mode_option_number(default_mode)
    profiles = scan_config.get("profiles", {})

    print_section("Scan Mode Selection")
    print_status("i", f"Default Scan Mode: {default_mode}")
    print()

    print("1) discovery")
    print(f"   {profiles.get('discovery', {}).get('description', '')}")
    print("2) basic")
    print(f"   {profiles.get('basic', {}).get('description', '')}")
    print("3) standard")
    print(f"   {profiles.get('standard', {}).get('description', '')}")
    print("4) deep")
    print(f"   {profiles.get('deep', {}).get('description', '')}")
    print()

    choice = input(f"Select scan mode for this run [{default_option}]: ").strip()

    if choice == "":
        selected_mode = default_mode
    elif choice in SCAN_MODE_OPTIONS:
        selected_mode = SCAN_MODE_OPTIONS[choice]
    else:
        print_status("!", "Invalid option. Using default scan mode")
        selected_mode = default_mode

    print_status("+", f"Selected Scan Mode: {selected_mode}")
    print()

    return selected_mode


# ------------------------------------------------------------
# PARSED OUTPUT DISPLAY
# ------------------------------------------------------------

def print_parsed_scan_summary(parsed_scan: dict) -> None:
    """Print a clean summary of parsed nmap scan data."""
    runstats = parsed_scan.get("runstats", {})
    hosts = parsed_scan.get("hosts", [])

    host_counts = runstats.get("hosts", {})
    elapsed_seconds = runstats.get("elapsed_seconds", "Unknown")

    print_status("i", f"Hosts Up: {host_counts.get('up', 0)}")
    print_status("i", f"Hosts Down: {host_counts.get('down', 0)}")
    print_status("i", f"Hosts Total: {host_counts.get('total', 0)}")
    print_status("i", f"Elapsed Seconds: {elapsed_seconds}")

    if not hosts:
        print_status("!", "No live hosts parsed from scan output")
        return

    print()

    for host in hosts:
        ipv4_address = host.get("ipv4_address", "Unknown")
        open_ports = host.get("open_ports", [])

        print_status("+", f"Host: {ipv4_address}")
        print(f"    Open Ports: {len(open_ports)}")

        for port in open_ports:
            service = port.get("service", {})
            service_name = service.get("name", "unknown")
            product = service.get("product", "")
            version = service.get("version", "")

            service_details = " ".join(
                value for value in (service_name, product, version) if value
            )

            print(
                f"    {port.get('port')}/{port.get('protocol')} "
                f"| {service_details}"
            )

        print()


# ------------------------------------------------------------
# CHANGE DETECTION DISPLAY
# ------------------------------------------------------------

def print_change_details(changes: dict) -> None:
    """Print detailed change detection results."""
    if changes["new_hosts"]:
        print()
        print_status("+", "New Hosts")
        for ipv4_address in changes["new_hosts"]:
            print(f"    {ipv4_address}")

    if changes["missing_hosts"]:
        print()
        print_status("!", "Missing Hosts")
        for ipv4_address in changes["missing_hosts"]:
            print(f"    {ipv4_address}")

    if changes["new_open_ports"]:
        print()
        print_status("+", "New Open Ports")
        for item in changes["new_open_ports"]:
            port = item["port"]
            print(
                f"    {item['ipv4_address']} "
                f"{port['port']}/{port['protocol']} "
                f"| {port['service_name']}"
            )

    if changes["closed_ports"]:
        print()
        print_status("!", "Closed Ports")
        for item in changes["closed_ports"]:
            port = item["port"]
            print(
                f"    {item['ipv4_address']} "
                f"{port['port']}/{port['protocol']} "
                f"| {port['service_name']}"
            )


# ------------------------------------------------------------
# CLEAR ARTEFACTS WORKFLOW
# ------------------------------------------------------------

def run_clear_artefacts() -> int:
    """Clear generated Sondar runtime artefacts."""
    print_main_header("Sondar - Clear Artefacts")

    try:
        print_section("Runtime Artefacts")

        print_status("*", "Preparing data directories")
        prepare_data_directories()
        print_status("+", "Data directories ready")

        print_status("*", "Clearing generated artefacts")
        removed = clear_runtime_artefacts()
        removed_count = count_removed_files(removed)

        print_status("+", f"Removed files: {removed_count}")

        for artefact_type, files in removed.items():
            print_status("i", f"{artefact_type}: {len(files)}")

        print()
        print_status("+", "Clear Artefacts completed")
        return 0

    except Exception as error:
        print()
        print_status("X", "Clear Artefacts failed")
        print_status("X", str(error))
        return 1


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the Sondar network scan workflow."""
    print_main_header("Sondar - Network Scan")

    try:
        print_section("Paths")
        print_status("*", "Preparing data directories")
        prepare_data_directories()
        print_status("+", f"Scans directory ready: {relative_path(SCANS_DIR)}")
        print_status("+", f"Reports directory ready: {relative_path(REPORTS_DIR)}")
        print_status("+", f"Logs directory ready: {relative_path(LOGS_DIR)}")
        print_status("+", f"Inventory directory ready: {relative_path(INVENTORY_DIR)}")
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
            "Default scan mode: %s",
            scan_config.get("scan_mode", "Not configured")
        )

        print_status("i", f"Project: {project_name}")
        print_status("i", f"Version: {version}")
        print_status(
            "i",
            f"Fallback Target: {scan_config.get('fallback_target', '')}"
        )
        print_status(
            "i",
            f"Default Scan Mode: {scan_config.get('scan_mode', 'Not configured')}"
        )
        print()

        print_section("Target Selection")
        print_status("*", "Detecting local network target")
        target_details = detect_scan_target(scan_config, logger)

        logger.info("Target source: %s", target_details["source"])
        logger.info("Adapter: %s", target_details["adapter"])
        logger.info("IPv4 address: %s", target_details["ipv4_address"])
        logger.info("Subnet mask: %s", target_details["subnet_mask"])
        logger.info("Suggested target: %s", target_details["cidr_target"])

        print_status("+", f"Target source: {target_details['source']}")
        print_status("i", f"Adapter: {target_details['adapter']}")
        print_status("i", f"IPv4 Address: {target_details['ipv4_address']}")
        print_status("i", f"Subnet Mask: {target_details['subnet_mask']}")
        print_status("+", f"Suggested Target: {target_details['cidr_target']}")

        selected_target = confirm_scan_target(target_details, scan_config, logger)
        print_status("+", f"Selected Target: {selected_target}")
        logger.info("Confirmed scan target: %s", selected_target)
        print()

        scan_mode = select_scan_mode_for_run(scan_config)
        timeout_seconds = scan_config.get("timeout_seconds", 300)

        logger.info("Selected scan mode for run: %s", scan_mode)

        print_section("Scan Execution")
        print_status("*", f"Running {scan_mode} network scan")

        scan_result = run_scan(selected_target, scan_mode, timeout_seconds)

        logger.info("Scan completed")
        logger.info("Scan command: %s", scan_result["command"])
        logger.info("Scan output: %s", scan_result["output_path"])

        print_status("+", "Scan completed")
        print_status("+", f"Raw scan saved: {scan_result['output_path']}")
        print_status("i", f"Scan Mode Used: {scan_result['scan_mode']}")
        print()

        print_section("Parse Results")
        print_status("*", "Parsing raw scan XML")

        parsed_scan = parse_nmap_xml(Path(scan_result["output_path"]))

        logger.info("Parsed hosts: %s", len(parsed_scan.get("hosts", [])))
        logger.info(
            "Parsed host totals: %s",
            parsed_scan.get("runstats", {}).get("hosts", {})
        )

        print_status("+", "Scan XML parsed")
        print_parsed_scan_summary(parsed_scan)

        print_section("Inventory")
        print_status("*", "Building inventory snapshot")

        inventory_result = save_inventory_snapshot(parsed_scan)
        inventory = inventory_result["inventory"]

        logger.info("Inventory snapshot saved: %s", inventory_result["display_path"])
        logger.info("Live hosts recorded: %s", inventory["summary"]["live_hosts_recorded"])
        logger.info("Open ports total: %s", inventory["summary"]["open_ports_total"])

        print_status("+", f"Inventory snapshot saved: {inventory_result['display_path']}")
        print_status(
            "i",
            f"Live Hosts Recorded: {inventory['summary']['live_hosts_recorded']}"
        )
        print_status("i", f"Open Ports Total: {inventory['summary']['open_ports_total']}")
        print()

        print_section("Change Detection")
        print_status("*", "Comparing inventory snapshots")

        change_result = detect_inventory_changes(
            inventory,
            inventory_result["output_path"],
        )

        if not change_result["has_previous_snapshot"]:
            changes = change_result["changes"]
            summary = changes["summary"]

            print_status("!", "Previous inventory snapshot not found")
            print_status("i", "Current inventory stored as baseline")

            if not summary.get("port_comparison_enabled", True):
                print_status("i", "Port Change Comparison: Skipped")
                print_status(
                    "i",
                    "Reason: current snapshot did not include port scan data"
                )

            logger.info("Previous inventory snapshot not found")
        else:
            changes = change_result["changes"]
            summary = changes["summary"]

            logger.info("Previous inventory: %s", change_result["previous_snapshot"])
            logger.info("Current inventory: %s", change_result["current_snapshot"])
            logger.info("New hosts: %s", summary["new_hosts"])
            logger.info("Missing hosts: %s", summary["missing_hosts"])
            logger.info("New open ports: %s", summary["new_open_ports"])
            logger.info("Closed ports: %s", summary["closed_ports"])
            logger.info(
                "Port comparison enabled: %s",
                summary.get("port_comparison_enabled", True)
            )

            print_status("+", "Change detection completed")
            print_status("i", f"Previous Snapshot: {change_result['previous_snapshot']}")
            print_status("i", f"New Hosts: {summary['new_hosts']}")
            print_status("i", f"Missing Hosts: {summary['missing_hosts']}")
            print_status("i", f"New Open Ports: {summary['new_open_ports']}")
            print_status("i", f"Closed Ports: {summary['closed_ports']}")

            if not summary.get("port_comparison_enabled", True):
                print_status("i", "Port Change Comparison: Skipped")
                print_status(
                    "i",
                    "Reason: one or more snapshots did not include port scan data"
                )

            print_change_details(changes)

        print()

        print_section("Report")
        print_status("*", "Writing Markdown report")

        report_result = save_markdown_report(
            project_name,
            version,
            selected_target,
            scan_config,
            scan_result,
            parsed_scan,
            inventory_result,
            change_result,
        )

        logger.info("Markdown report saved: %s", report_result["display_path"])

        print_status("+", f"Report saved: {report_result['display_path']}")
        print()

        print_status("+", "Network Scan completed")
        return 0

    except Exception as error:
        print()
        print_status("X", "Network Scan failed")
        print_status("X", str(error))
        return 1


# ------------------------------------------------------------
# MENU WORKFLOW
# ------------------------------------------------------------

def print_menu() -> None:
    """Print the Sondar main menu."""
    print_main_header("Sondar")

    print("1) Network Scan")
    print("2) Clear Artefacts")
    print("3) Exit")
    print()
    print("=" * 60)
    print()


def pause_before_menu() -> None:
    """Pause before returning to the main menu."""
    print()
    input("Press Enter to return to the menu...")


def run_menu() -> int:
    """Run the Sondar interactive menu."""
    while True:
        print_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            main()
            pause_before_menu()
            continue

        if choice == "2":
            run_clear_artefacts()
            pause_before_menu()
            continue

        if choice == "3":
            print()
            print_status("+", "Sondar closed")
            return 0

        print()
        print_status("!", "Invalid option. Select 1, 2, or 3")
        pause_before_menu()


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    args = parse_arguments()

    if args.clear_artefacts:
        sys.exit(run_clear_artefacts())

    if args.scan:
        sys.exit(main())

    sys.exit(run_menu())