"""
Sondar network target detection.

Detects a likely local IPv4 network target for authorised home/lab scanning.
This module does not run scans. It only identifies and prepares a suggested
CIDR target for the scanner to use later.
"""

import ipaddress
import socket
import subprocess


# ------------------------------------------------------------
# NETWORK FILTERS
# ------------------------------------------------------------

def is_usable_ipv4(address: str) -> bool:
    """
    Return True if an IPv4 address is suitable for local network detection.
    """
    try:
        ip_address = ipaddress.ip_address(address)
    except ValueError:
        return False

    if ip_address.version != 4:
        return False

    if ip_address.is_loopback:
        return False

    if ip_address.is_link_local:
        return False

    if ip_address.is_multicast:
        return False

    if ip_address.is_unspecified:
        return False

    return True


# ------------------------------------------------------------
# TARGET CALCULATION
# ------------------------------------------------------------

def calculate_cidr_target(ipv4_address: str, subnet_mask: str) -> str:
    """
    Calculate a CIDR network target from an IPv4 address and subnet mask.
    """
    interface = ipaddress.ip_interface(f"{ipv4_address}/{subnet_mask}")
    return str(interface.network)


# ------------------------------------------------------------
# WINDOWS IPCONFIG PARSING
# ------------------------------------------------------------

def parse_ipconfig_output(output: str) -> list[dict[str, str]]:
    """
    Parse Windows ipconfig output and return detected IPv4 interface details.

    Returned dictionaries contain:
        adapter
        ipv4_address
        subnet_mask
        cidr_target
    """
    interfaces = []
    current_adapter = None
    current_ipv4 = None
    current_mask = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.endswith(":") and "adapter" in line.lower():
            current_adapter = line.rstrip(":")
            current_ipv4 = None
            current_mask = None
            continue

        if "IPv4 Address" in line:
            current_ipv4 = line.split(":", 1)[1].strip()
            current_ipv4 = current_ipv4.replace("(Preferred)", "").strip()
            continue

        if "Subnet Mask" in line:
            current_mask = line.split(":", 1)[1].strip()

        if current_adapter and current_ipv4 and current_mask:
            if is_usable_ipv4(current_ipv4):
                cidr_target = calculate_cidr_target(current_ipv4, current_mask)

                interfaces.append(
                    {
                        "adapter": current_adapter,
                        "ipv4_address": current_ipv4,
                        "subnet_mask": current_mask,
                        "cidr_target": cidr_target,
                    }
                )

            current_ipv4 = None
            current_mask = None

    return interfaces


# ------------------------------------------------------------
# TARGET DETECTION
# ------------------------------------------------------------

def detect_windows_interfaces() -> list[dict[str, str]]:
    """
    Run ipconfig and return usable Windows IPv4 interface details.
    """
    result = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError("ipconfig command failed")

    return parse_ipconfig_output(result.stdout)


def get_primary_target(fallback_target: str) -> dict[str, str]:
    """
    Return the primary detected scan target.

    If no usable local interface is detected, return the configured fallback
    target instead.
    """
    interfaces = detect_windows_interfaces()

    if not interfaces:
        return {
            "source": "fallback",
            "adapter": "Not detected",
            "ipv4_address": "Not detected",
            "subnet_mask": "Not detected",
            "cidr_target": fallback_target,
        }

    primary_interface = interfaces[0]

    return {
        "source": "auto-detected",
        "adapter": primary_interface["adapter"],
        "ipv4_address": primary_interface["ipv4_address"],
        "subnet_mask": primary_interface["subnet_mask"],
        "cidr_target": primary_interface["cidr_target"],
    }