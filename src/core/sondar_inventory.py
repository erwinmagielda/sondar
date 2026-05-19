"""
Sondar inventory management.

Builds a normalised inventory snapshot from parsed scan data and writes it as
structured JSON for later change detection and reporting.
"""

import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from utils.sondar_paths import INVENTORY_DIR, relative_path


# ------------------------------------------------------------
# INVENTORY NORMALISATION
# ------------------------------------------------------------

def normalise_service(service: dict[str, Any]) -> dict[str, str]:
    """Return a clean service dictionary for inventory storage."""
    return {
        "name": service.get("name", "unknown"),
        "product": service.get("product", ""),
        "version": service.get("version", ""),
        "extra_info": service.get("extra_info", ""),
        "ostype": service.get("ostype", ""),
        "method": service.get("method", ""),
        "confidence": service.get("confidence", ""),
    }


def normalise_port(port: dict[str, Any]) -> dict[str, Any]:
    """Return a clean open-port dictionary for inventory storage."""
    return {
        "protocol": port.get("protocol", "unknown"),
        "port": port.get("port", 0),
        "state": port.get("state", "unknown"),
        "service": normalise_service(port.get("service", {})),
        "cpes": port.get("cpes", []),
    }


def normalise_host(host: dict[str, Any]) -> dict[str, Any]:
    """Return a clean host dictionary for inventory storage."""
    open_ports = host.get("open_ports", [])

    return {
        "ipv4_address": host.get("ipv4_address", "Unknown"),
        "hostnames": host.get("hostnames", []),
        "status": host.get("status", "unknown"),
        "open_port_count": len(open_ports),
        "open_ports": [normalise_port(port) for port in open_ports],
    }


# ------------------------------------------------------------
# INVENTORY BUILDING
# ------------------------------------------------------------

def build_inventory_snapshot(parsed_scan: dict[str, Any]) -> dict[str, Any]:
    """
    Build a normalised inventory snapshot from parsed scan data.
    """
    hosts = parsed_scan.get("hosts", [])
    runstats = parsed_scan.get("runstats", {})
    metadata = parsed_scan.get("metadata", {})

    normalised_hosts = [normalise_host(host) for host in hosts]

    return {
        "inventory_metadata": {
            "created_utc": datetime.now(UTC).isoformat(),
            "source": "nmap_xml",
            "scanner": metadata.get("scanner", "nmap"),
            "scanner_version": metadata.get("version", ""),
            "scan_start": metadata.get("start_string", ""),
            "scan_args": metadata.get("args", ""),
            "source_xml": metadata.get("xml_path", ""),
        },
        "summary": {
            "hosts_up": runstats.get("hosts", {}).get("up", 0),
            "hosts_down": runstats.get("hosts", {}).get("down", 0),
            "hosts_total": runstats.get("hosts", {}).get("total", 0),
            "live_hosts_recorded": len(normalised_hosts),
            "open_ports_total": sum(
                host["open_port_count"] for host in normalised_hosts
            ),
            "elapsed_seconds": runstats.get("elapsed_seconds", ""),
        },
        "hosts": normalised_hosts,
    }


# ------------------------------------------------------------
# INVENTORY EXPORT
# ------------------------------------------------------------

def write_inventory_snapshot(inventory_snapshot: dict[str, Any]) -> Path:
    """
    Write an inventory snapshot to data/inventory and return the output path.
    """
    INVENTORY_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = INVENTORY_DIR / f"sondar_inventory_{timestamp}.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(inventory_snapshot, file, indent=4)

    return output_path


def save_inventory_snapshot(parsed_scan: dict[str, Any]) -> dict[str, Any]:
    """
    Build and write an inventory snapshot.

    Returns inventory data and output path details.
    """
    inventory_snapshot = build_inventory_snapshot(parsed_scan)
    output_path = write_inventory_snapshot(inventory_snapshot)

    return {
        "inventory": inventory_snapshot,
        "output_path": output_path,
        "display_path": relative_path(output_path),
    }