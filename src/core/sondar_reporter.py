"""
Sondar report generation.

Builds a readable Markdown report from scan execution, parsed results,
inventory data, and change detection output.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from utils.sondar_paths import REPORTS_DIR, relative_path


# ------------------------------------------------------------
# FORMAT HELPERS
# ------------------------------------------------------------

def format_change_port(item: dict[str, Any]) -> str:
    """Return a compact changed-port description."""
    port = item.get("port", {})

    values = [
        f"{item.get('ipv4_address', 'Unknown')}",
        f"{port.get('port', 0)}/{port.get('protocol', 'unknown')}",
        f"| {port.get('service_name', 'unknown')}",
    ]

    return " ".join(values)


def format_bool(value: bool) -> str:
    """Return a readable boolean value for reports."""
    return "yes" if value else "no"


def format_port_comparison_state(value: bool) -> str:
    """Return a readable port comparison state."""
    return "enabled" if value else "skipped"


# ------------------------------------------------------------
# REPORT SECTIONS
# ------------------------------------------------------------

def build_report_header(project_name: str, version: str) -> list[str]:
    """Build the report title section."""
    return [
        f"# {project_name} scan report",
        "",
        f"Generated UTC: {datetime.now(UTC).isoformat()}",
        f"Tool version: {version}",
        "",
    ]


def build_scan_summary_section(
    selected_target: str,
    scan_config: dict[str, Any],
    scan_result: dict[str, Any],
    parsed_scan: dict[str, Any],
    inventory_result: dict[str, Any],
) -> list[str]:
    """Build the scan summary section."""
    runstats = parsed_scan.get("runstats", {})
    host_counts = runstats.get("hosts", {})
    inventory = inventory_result.get("inventory", {})
    inventory_metadata = inventory.get("inventory_metadata", {})
    inventory_summary = inventory.get("summary", {})

    selected_scan_mode = scan_result.get(
        "scan_mode",
        scan_config.get("scan_mode", "basic"),
    )

    port_scan_enabled = inventory_metadata.get("port_scan_enabled", True)

    return [
        "## Scan summary",
        "",
        f"- Target: `{selected_target}`",
        f"- Scan mode: `{selected_scan_mode}`",
        f"- Inventory scan mode: `{inventory_metadata.get('scan_mode', 'unknown')}`",
        f"- Port scan enabled: {format_bool(port_scan_enabled)}",
        f"- Raw XML: `{scan_result.get('output_path', '')}`",
        f"- Inventory snapshot: `{inventory_result.get('display_path', '')}`",
        f"- Hosts up: {host_counts.get('up', 0)}",
        f"- Hosts down: {host_counts.get('down', 0)}",
        f"- Hosts total: {host_counts.get('total', 0)}",
        f"- Live hosts recorded: {inventory_summary.get('live_hosts_recorded', 0)}",
        f"- Open ports total: {inventory_summary.get('open_ports_total', 0)}",
        f"- Elapsed seconds: {runstats.get('elapsed_seconds', '')}",
        "",
    ]


def build_host_inventory_section(inventory: dict[str, Any]) -> list[str]:
    """Build the host inventory section."""
    lines = [
        "## Host inventory",
        "",
    ]

    hosts = inventory.get("hosts", [])

    if not hosts:
        lines.extend(
            [
                "No live hosts were recorded in this inventory snapshot.",
                "",
            ]
        )
        return lines

    for host in hosts:
        ipv4_address = host.get("ipv4_address", "Unknown")
        open_ports = host.get("open_ports", [])

        lines.extend(
            [
                f"### {ipv4_address}",
                "",
                f"- Status: {host.get('status', 'unknown')}",
                f"- Hostnames: {', '.join(host.get('hostnames', [])) or 'none'}",
                f"- Open ports: {len(open_ports)}",
                "",
            ]
        )

        if not open_ports:
            lines.extend(["No open ports recorded.", ""])
            continue

        lines.extend(
            [
                "| Port | Protocol | Service | Product | Version |",
                "|---:|---|---|---|---|",
            ]
        )

        for port in open_ports:
            service = port.get("service", {})

            lines.append(
                "| "
                f"{port.get('port', 0)} | "
                f"{port.get('protocol', 'unknown')} | "
                f"{service.get('name', 'unknown')} | "
                f"{service.get('product', '')} | "
                f"{service.get('version', '')} |"
            )

        lines.append("")

    return lines


def build_change_detection_section(change_result: dict[str, Any]) -> list[str]:
    """Build the change detection section."""
    lines = [
        "## Change detection",
        "",
    ]

    changes = change_result.get("changes", {})
    summary = changes.get("summary", {})
    port_comparison_enabled = summary.get("port_comparison_enabled", True)
    port_comparison_state = format_port_comparison_state(port_comparison_enabled)

    if not change_result.get("has_previous_snapshot", False):
        lines.extend(
            [
                "No previous inventory snapshot was found.",
                "",
                "The current inventory has been stored as the baseline for future comparisons.",
                "",
                f"- Port change comparison: {port_comparison_state}",
                "",
            ]
        )

        if not port_comparison_enabled:
            lines.extend(
                [
                    "Port change comparison was skipped because the current snapshot did not include port scan data.",
                    "",
                ]
            )

        return lines

    lines.extend(
        [
            f"- Previous snapshot: `{change_result.get('previous_snapshot', '')}`",
            f"- Current snapshot: `{change_result.get('current_snapshot', '')}`",
            f"- New hosts: {summary.get('new_hosts', 0)}",
            f"- Missing hosts: {summary.get('missing_hosts', 0)}",
            f"- New open ports: {summary.get('new_open_ports', 0)}",
            f"- Closed ports: {summary.get('closed_ports', 0)}",
            f"- Port change comparison: {port_comparison_state}",
            "",
        ]
    )

    if not port_comparison_enabled:
        lines.extend(
            [
                "Port change comparison was skipped because one or more snapshots did not include port scan data.",
                "",
            ]
        )

    if changes.get("new_hosts"):
        lines.extend(["### New hosts", ""])
        for ipv4_address in changes["new_hosts"]:
            lines.append(f"- {ipv4_address}")
        lines.append("")

    if changes.get("missing_hosts"):
        lines.extend(["### Missing hosts", ""])
        for ipv4_address in changes["missing_hosts"]:
            lines.append(f"- {ipv4_address}")
        lines.append("")

    if port_comparison_enabled and changes.get("new_open_ports"):
        lines.extend(["### New open ports", ""])
        for item in changes["new_open_ports"]:
            lines.append(f"- {format_change_port(item)}")
        lines.append("")

    if port_comparison_enabled and changes.get("closed_ports"):
        lines.extend(["### Closed ports", ""])
        for item in changes["closed_ports"]:
            lines.append(f"- {format_change_port(item)}")
        lines.append("")

    return lines


# ------------------------------------------------------------
# REPORT BUILDING
# ------------------------------------------------------------

def build_markdown_report(
    project_name: str,
    version: str,
    selected_target: str,
    scan_config: dict[str, Any],
    scan_result: dict[str, Any],
    parsed_scan: dict[str, Any],
    inventory_result: dict[str, Any],
    change_result: dict[str, Any],
) -> str:
    """Build the full Sondar Markdown report."""
    inventory = inventory_result.get("inventory", {})

    lines = []
    lines.extend(build_report_header(project_name, version))
    lines.extend(
        build_scan_summary_section(
            selected_target,
            scan_config,
            scan_result,
            parsed_scan,
            inventory_result,
        )
    )
    lines.extend(build_host_inventory_section(inventory))
    lines.extend(build_change_detection_section(change_result))

    return "\n".join(lines)


# ------------------------------------------------------------
# REPORT EXPORT
# ------------------------------------------------------------

def write_markdown_report(report_content: str) -> Path:
    """Write a Markdown report to data/reports and return the output path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = REPORTS_DIR / f"sondar_report_{timestamp}.md"

    with output_path.open("w", encoding="utf-8") as file:
        file.write(report_content)

    return output_path


def save_markdown_report(
    project_name: str,
    version: str,
    selected_target: str,
    scan_config: dict[str, Any],
    scan_result: dict[str, Any],
    parsed_scan: dict[str, Any],
    inventory_result: dict[str, Any],
    change_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Build and save a Markdown report.

    Returns report path details.
    """
    report_content = build_markdown_report(
        project_name,
        version,
        selected_target,
        scan_config,
        scan_result,
        parsed_scan,
        inventory_result,
        change_result,
    )

    output_path = write_markdown_report(report_content)

    return {
        "output_path": output_path,
        "display_path": relative_path(output_path),
    }