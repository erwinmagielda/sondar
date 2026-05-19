"""
Sondar change detection.

Compares inventory snapshots to identify new hosts, missing hosts, newly open
ports, and closed ports between scans.
"""

import json
from pathlib import Path
from typing import Any

from utils.sondar_paths import INVENTORY_DIR, relative_path


# ------------------------------------------------------------
# INVENTORY LOADING
# ------------------------------------------------------------

def list_inventory_snapshots() -> list[Path]:
    """
    Return inventory snapshot files sorted by modified time.
    """
    if not INVENTORY_DIR.exists():
        return []

    snapshots = list(INVENTORY_DIR.glob("sondar_inventory_*.json"))
    return sorted(snapshots, key=lambda path: path.stat().st_mtime)


def load_inventory_snapshot(path: Path) -> dict[str, Any]:
    """
    Load an inventory snapshot from disk.
    """
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_previous_inventory(current_path: Path) -> dict[str, Any] | None:
    """
    Return the inventory snapshot before the current snapshot.

    If no previous snapshot exists, return None.
    """
    snapshots = list_inventory_snapshots()

    previous_snapshots = [
        snapshot for snapshot in snapshots
        if snapshot.resolve() != current_path.resolve()
    ]

    if not previous_snapshots:
        return None

    previous_path = previous_snapshots[-1]

    return {
        "path": previous_path,
        "display_path": relative_path(previous_path),
        "inventory": load_inventory_snapshot(previous_path),
    }


# ------------------------------------------------------------
# COMPARISON HELPERS
# ------------------------------------------------------------

def index_hosts_by_ip(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Return inventory hosts indexed by IPv4 address.
    """
    return {
        host.get("ipv4_address", "Unknown"): host
        for host in inventory.get("hosts", [])
    }


def build_port_key(port: dict[str, Any]) -> str:
    """
    Build a stable comparison key for an open port.
    """
    return f"{port.get('protocol', 'unknown')}/{port.get('port', 0)}"


def index_ports(host: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Return a host's open ports indexed by protocol/port.
    """
    return {
        build_port_key(port): port
        for port in host.get("open_ports", [])
    }


def describe_port(port: dict[str, Any]) -> dict[str, Any]:
    """
    Return a compact port description for change output.
    """
    service = port.get("service", {})

    return {
        "port": port.get("port", 0),
        "protocol": port.get("protocol", "unknown"),
        "service_name": service.get("name", "unknown"),
        "product": service.get("product", ""),
        "version": service.get("version", ""),
    }


# ------------------------------------------------------------
# CHANGE DETECTION
# ------------------------------------------------------------

def compare_inventories(
    previous_inventory: dict[str, Any],
    current_inventory: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare two inventory snapshots and return detected changes.
    """
    previous_hosts = index_hosts_by_ip(previous_inventory)
    current_hosts = index_hosts_by_ip(current_inventory)

    previous_ips = set(previous_hosts.keys())
    current_ips = set(current_hosts.keys())

    new_hosts = sorted(current_ips - previous_ips)
    missing_hosts = sorted(previous_ips - current_ips)
    common_hosts = sorted(previous_ips & current_ips)

    new_open_ports = []
    closed_ports = []

    for ipv4_address in common_hosts:
        previous_ports = index_ports(previous_hosts[ipv4_address])
        current_ports = index_ports(current_hosts[ipv4_address])

        previous_port_keys = set(previous_ports.keys())
        current_port_keys = set(current_ports.keys())

        for port_key in sorted(current_port_keys - previous_port_keys):
            new_open_ports.append(
                {
                    "ipv4_address": ipv4_address,
                    "port_key": port_key,
                    "port": describe_port(current_ports[port_key]),
                }
            )

        for port_key in sorted(previous_port_keys - current_port_keys):
            closed_ports.append(
                {
                    "ipv4_address": ipv4_address,
                    "port_key": port_key,
                    "port": describe_port(previous_ports[port_key]),
                }
            )

    return {
        "new_hosts": new_hosts,
        "missing_hosts": missing_hosts,
        "new_open_ports": new_open_ports,
        "closed_ports": closed_ports,
        "summary": {
            "new_hosts": len(new_hosts),
            "missing_hosts": len(missing_hosts),
            "new_open_ports": len(new_open_ports),
            "closed_ports": len(closed_ports),
        },
    }


def detect_inventory_changes(current_inventory: dict[str, Any], current_path: Path) -> dict[str, Any]:
    """
    Detect changes between the current inventory and the previous snapshot.
    """
    previous = get_previous_inventory(current_path)

    if previous is None:
        return {
            "has_previous_snapshot": False,
            "previous_snapshot": "",
            "current_snapshot": relative_path(current_path),
            "changes": {
                "new_hosts": [],
                "missing_hosts": [],
                "new_open_ports": [],
                "closed_ports": [],
                "summary": {
                    "new_hosts": 0,
                    "missing_hosts": 0,
                    "new_open_ports": 0,
                    "closed_ports": 0,
                },
            },
        }

    changes = compare_inventories(previous["inventory"], current_inventory)

    return {
        "has_previous_snapshot": True,
        "previous_snapshot": previous["display_path"],
        "current_snapshot": relative_path(current_path),
        "changes": changes,
    }