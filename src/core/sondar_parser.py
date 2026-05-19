"""
Sondar scan parser.

Parses raw nmap XML output into clean Python dictionaries for inventory,
change detection, and reporting.
"""

import xml.etree.ElementTree as ET
from pathlib import Path


# ------------------------------------------------------------
# XML HELPERS
# ------------------------------------------------------------

def get_text_list(parent: ET.Element, tag_name: str) -> list[str]:
    """
    Return text values for matching child tags.

    Empty values are ignored.
    """
    values = []

    for element in parent.findall(tag_name):
        if element.text:
            values.append(element.text.strip())

    return values


def get_host_address(host: ET.Element) -> str:
    """
    Return the IPv4 address for a host element.
    """
    for address in host.findall("address"):
        if address.attrib.get("addrtype") == "ipv4":
            return address.attrib.get("addr", "Unknown")

    return "Unknown"


def get_hostnames(host: ET.Element) -> list[str]:
    """
    Return hostnames reported for a host element.
    """
    hostnames = []

    hostnames_element = host.find("hostnames")
    if hostnames_element is None:
        return hostnames

    for hostname in hostnames_element.findall("hostname"):
        name = hostname.attrib.get("name")
        if name:
            hostnames.append(name)

    return hostnames


# ------------------------------------------------------------
# PORT PARSING
# ------------------------------------------------------------

def parse_port(port: ET.Element) -> dict:
    """
    Parse one nmap port element into a dictionary.
    """
    state_element = port.find("state")
    service_element = port.find("service")

    state = state_element.attrib.get("state", "unknown") if state_element is not None else "unknown"

    service = {}
    cpes = []

    if service_element is not None:
        service = {
            "name": service_element.attrib.get("name", "unknown"),
            "product": service_element.attrib.get("product", ""),
            "version": service_element.attrib.get("version", ""),
            "extra_info": service_element.attrib.get("extrainfo", ""),
            "ostype": service_element.attrib.get("ostype", ""),
            "method": service_element.attrib.get("method", ""),
            "confidence": service_element.attrib.get("conf", ""),
        }
        cpes = get_text_list(service_element, "cpe")
    else:
        service = {
            "name": "unknown",
            "product": "",
            "version": "",
            "extra_info": "",
            "ostype": "",
            "method": "",
            "confidence": "",
        }

    return {
        "protocol": port.attrib.get("protocol", "unknown"),
        "port": int(port.attrib.get("portid", 0)),
        "state": state,
        "service": service,
        "cpes": cpes,
    }


def parse_ports(host: ET.Element) -> list[dict]:
    """
    Parse open ports from a host element.

    Closed and filtered ports are ignored for the initial inventory view.
    """
    parsed_ports = []

    ports_element = host.find("ports")
    if ports_element is None:
        return parsed_ports

    for port in ports_element.findall("port"):
        parsed_port = parse_port(port)

        if parsed_port["state"] == "open":
            parsed_ports.append(parsed_port)

    return parsed_ports


# ------------------------------------------------------------
# HOST PARSING
# ------------------------------------------------------------

def parse_host(host: ET.Element) -> dict:
    """
    Parse one nmap host element into a dictionary.
    """
    status_element = host.find("status")
    status = status_element.attrib.get("state", "unknown") if status_element is not None else "unknown"

    return {
        "ipv4_address": get_host_address(host),
        "hostnames": get_hostnames(host),
        "status": status,
        "open_ports": parse_ports(host),
    }


def parse_hosts(root: ET.Element) -> list[dict]:
    """
    Parse all host elements from an nmap XML root element.
    """
    hosts = []

    for host in root.findall("host"):
        parsed_host = parse_host(host)

        if parsed_host["status"] == "up":
            hosts.append(parsed_host)

    return hosts


# ------------------------------------------------------------
# RUN METADATA
# ------------------------------------------------------------

def parse_runstats(root: ET.Element) -> dict:
    """
    Parse nmap run statistics from the XML root element.
    """
    runstats = root.find("runstats")

    if runstats is None:
        return {
            "elapsed_seconds": "",
            "summary": "",
            "hosts": {
                "up": 0,
                "down": 0,
                "total": 0,
            },
        }

    finished = runstats.find("finished")
    hosts = runstats.find("hosts")

    return {
        "elapsed_seconds": finished.attrib.get("elapsed", "") if finished is not None else "",
        "summary": finished.attrib.get("summary", "") if finished is not None else "",
        "hosts": {
            "up": int(hosts.attrib.get("up", 0)) if hosts is not None else 0,
            "down": int(hosts.attrib.get("down", 0)) if hosts is not None else 0,
            "total": int(hosts.attrib.get("total", 0)) if hosts is not None else 0,
        },
    }


def parse_scan_metadata(root: ET.Element, xml_path: Path) -> dict:
    """
    Parse high-level scan metadata from the XML root element.
    """
    return {
        "scanner": root.attrib.get("scanner", "nmap"),
        "args": root.attrib.get("args", ""),
        "start": root.attrib.get("start", ""),
        "start_string": root.attrib.get("startstr", ""),
        "version": root.attrib.get("version", ""),
        "xml_path": str(xml_path),
    }


# ------------------------------------------------------------
# MAIN PARSER
# ------------------------------------------------------------

def parse_nmap_xml(xml_path: Path) -> dict:
    """
    Parse an nmap XML file into a structured scan dictionary.
    """
    if not xml_path.exists():
        raise FileNotFoundError(f"Scan XML not found: {xml_path}")

    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts = parse_hosts(root)
    runstats = parse_runstats(root)
    metadata = parse_scan_metadata(root, xml_path)

    return {
        "metadata": metadata,
        "runstats": runstats,
        "hosts": hosts,
    }