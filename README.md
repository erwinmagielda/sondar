# Sondar

**Network scan analysis, service inventory, and change detection.**

Sondar is a Python-based network visibility workflow that turns Nmap XML output into structured host inventory, service evidence, change detection results, and Markdown reports.

The project addresses a practical visibility problem:

> A scan shows what is visible at one point in time. Sondar preserves that evidence, turns it into inventory state, and compares future scans so host and service changes can be reviewed.

Sondar is designed for authorised lab and small-network environments where scan scope is explicitly confirmed by the operator before execution.

---

## Purpose

| Focus | Description |
|---|---|
| Network Visibility | Sondar identifies live hosts and exposed services using selected Nmap scan profiles, then presents the results through structured terminal output and report artefacts. |
| Operator Control | The workflow detects a suggested CIDR range, displays adapter and subnet evidence, and requires confirmation or manual override before any scan is executed. |
| Structured Evidence | Raw XML is preserved, parsed into host and service data, normalised into JSON inventory snapshots, and summarised in Markdown reports. |
| Change Detection | Current inventory state is compared against the previous snapshot to identify new hosts, missing hosts, newly open ports, and closed ports. |
| Portfolio Value | The project demonstrates Python workflow design, subprocess control, XML parsing, JSON artefact handling, network scan interpretation, and clean CLI operation. |

---

## Screenshot Evidence

The screenshots below show Sondar running end-to-end as an operator-facing workflow.

| Stage | Evidence |
|---|---|
| ![Operator Menu](assets/operator_menu.png) | **Operator Menu** - provides a controlled entry point for network scanning, artefact cleanup, and workflow exit. |
| ![Host Configuration](assets/host_configuration.png) | **Host Configuration** - prepares runtime directories, initialises logging, loads configuration, and displays clean repository-relative paths. |
| ![Scan Configuration](assets/scan_configuration.png) | **Scan Configuration** - detects the local IPv4 target, shows adapter and subnet evidence, asks for confirmation, and allows per-run scan profile selection. |
| ![Scan Execution](assets/scan_execution.png) | **Scan Execution** - runs the selected Nmap profile, saves raw XML, parses live hosts, and prints detected service exposure. |
| ![Change Detection](assets/change_detection.png) | **Change Detection** - compares the current inventory with the previous snapshot and reports newly open services. |
| ![Markdown Report](assets/markdown_report.png) | **Markdown Report** - converts scan and comparison output into a readable report for review. |
| ![Clear Artefacts](assets/clearing_artefacts.png) | **Clear Artefacts** - removes generated logs, scans, reports, inventory snapshots, and Python cache folders while preserving repository structure. |

---

## Technical Capabilities

| Area | Implementation |
|---|---|
| Core Stack | Python standard library, Windows batch launcher, Nmap XML output, JSON inventory snapshots, Markdown reporting, and repository-relative runtime paths. |
| Target Handling | Parses Windows interface data, identifies a usable IPv4 address and subnet mask, calculates a CIDR target, and requires operator confirmation before scan execution. |
| Scan Control | Supports discovery, basic, standard, and deep scan profiles selected per run, allowing scan depth to change without permanently editing the configuration file. |
| XML Processing | Parses Nmap XML into structured host, hostname, port, protocol, state, service, product, version, CPE, and run-statistics data. |
| Inventory State | Converts parsed scan results into timestamped JSON inventory snapshots with metadata describing scan mode and port-scan availability. |
| Change Detection | Compares inventory snapshots by host IP and protocol/port keys to identify new hosts, missing hosts, newly open ports, and closed ports. |
| Scan Context | Tracks whether a scan profile collected port data so discovery scans do not create false closed-port findings when compared against service scans. |
| Reporting | Generates Markdown reports containing scan summary, host inventory, open service tables, previous snapshot reference, and detected changes. |
| Artefact Control | Stores raw scans, logs, reports, and inventory snapshots under `data/`, then clears generated runtime artefacts while preserving `.gitkeep` placeholders. |

---

## Architecture

The architecture separates target detection, scan execution, XML parsing, inventory creation, change detection, report generation, logging, and artefact cleanup. This modularity makes the project easier to inspect, test, explain, and extend.

```text
sondar.bat
│   Launches the interactive operator workflow from the repository root.
│   Checks Python and Nmap availability before opening the menu.
│
config/
│   └── sondar_config.json
│       Stores default scan behaviour, target confirmation settings,
│       timeout values, and scan profile descriptions.
│
data/
├── scans/
│   Stores raw Nmap XML scan artefacts.
│
├── inventory/
│   Stores normalised JSON inventory snapshots.
│
├── reports/
│   Stores generated Markdown scan reports.
│
└── logs/
    Stores timestamped runtime logs.
│
src/
├── sondar_main.py
│   Provides menu operation, workflow orchestration, target confirmation,
│   per-run scan mode selection, and stage-level terminal output.
│
├── core/
│   ├── sondar_network.py
│   │   Detects local IPv4 interface data and calculates a suggested CIDR target.
│   │
│   ├── sondar_scanner.py
│   │   Builds Nmap commands from scan profiles and writes raw XML output.
│   │
│   ├── sondar_parser.py
│   │   Parses Nmap XML into structured host, port, service, and run data.
│   │
│   ├── sondar_inventory.py
│   │   Builds normalised JSON inventory snapshots from parsed scan data.
│   │
│   ├── sondar_detector.py
│   │   Compares inventory snapshots and reports host or service changes.
│   │
│   ├── sondar_reporter.py
│   │   Generates Markdown reports from scan, inventory, and change data.
│   │
│   └── sondar_artefacts.py
│       Clears generated runtime artefacts while preserving repository structure.
│
└── utils/
    ├── sondar_banner.py
    │   Provides the ASCII logo, headers, section labels, and status markers.
    │
    ├── sondar_logger.py
    │   Creates timestamped runtime logs.
    │
    └── sondar_paths.py
        Centralises repository paths and clean relative path output.
```

Each layer communicates through structured Python dictionaries, JSON artefacts, XML files, or Markdown reports. Raw scan evidence is preserved, while derived artefacts make the results easier to inspect without re-running the scan.

---

## Workflow

Sondar follows an explicit evidence chain from target selection to report generation:

```text
Target Detection -> Target Confirmation -> Scan Profile Selection -> Nmap XML Collection -> XML Parsing -> Inventory Snapshot -> Change Detection -> Markdown Report
```

The workflow keeps scan scope visible before execution and preserves each output stage for review. Raw XML remains available as original evidence, JSON inventory snapshots preserve comparable state, and Markdown reports provide readable summaries for manual inspection.

---

## Operation

| Action | Behaviour |
|---|---|
| Network Scan | Detects the local target, asks for confirmation or manual CIDR override, selects the scan mode for the current run, executes Nmap, parses XML, creates inventory, detects changes, and writes a report. |
| Clear Artefacts | Removes generated logs, scan XML files, Markdown reports, inventory snapshots, and Python cache directories while preserving repository placeholders. |
| Exit | Closes the operator menu cleanly. |

| Scan Mode | Nmap Behaviour | Use Case |
|---|---|---|
| `discovery` | `nmap -sn` | Host discovery without port scanning. |
| `basic` | `nmap -sV --top-ports 100` | Fast service snapshot using common TCP ports. |
| `standard` | `nmap -sV --top-ports 1000` | Broader service review with wider port coverage. |
| `deep` | `nmap -sV -p-` | Full TCP range service scan for authorised deeper review. |

| Artefact | Location | Purpose |
|---|---|---|
| Raw XML | `data/scans/` | Preserves original Nmap output for review and re-parsing. |
| Inventory JSON | `data/inventory/` | Stores normalised host and service state for comparison. |
| Markdown Report | `data/reports/` | Provides readable scan and change detection output. |
| Runtime Log | `data/logs/` | Records workflow activity, selected target, scan mode, and generated paths. |

Run from the repository root:

```bat
sondar.bat
```

Direct commands are also supported:

```bat
python src\sondar_main.py --scan
python src\sondar_main.py --clear-artefacts
```

---

## Technical Method

| Stage | Method | Output |
|---|---|---|
| Target Detection | Windows interface output is parsed to identify IPv4 address and subnet data, then Python `ipaddress` calculates the suggested CIDR range. | Confirmed scan target. |
| Scan Execution | Python `subprocess` runs the selected Nmap command with XML output enabled and stores the result under `data/scans/`. | Raw Nmap XML file. |
| XML Parsing | Python `xml.etree.ElementTree` extracts hosts, addresses, hostnames, ports, services, versions, CPEs, and run statistics. | Structured parsed scan dictionary. |
| Inventory Creation | Parsed scan data is normalised into a timestamped JSON snapshot with scan mode metadata and port-scan context. | Comparable inventory state. |
| Change Detection | Previous and current inventories are indexed by host IP and protocol/port keys, then compared for host and service changes. | Change summary and detailed findings. |
| Reporting | Scan metadata, inventory summary, host tables, and change results are assembled into a Markdown report. | Reviewable report artefact. |

Sondar uses Nmap as the scan engine because Nmap already provides mature host discovery, port scanning, service detection, and XML output. Sondar focuses on the controlled workflow around that engine: target confirmation, profile selection, artefact preservation, parsing, inventory state, comparison, and reporting.

---

## Setup

| Requirement | Detail |
|---|---|
| Python | Required to run the Sondar workflow. Python 3.13 was used during development. |
| Nmap | Required as the external scan engine. It must be installed and available in PATH. |
| Windows | The launcher and interface parsing are currently Windows-focused. |

Sondar currently uses Python standard-library modules only. No Python packages need to be installed with pip.

Check dependencies:

```bat
python --version
nmap --version
```

Launch the operator workflow:

```bat
sondar.bat
```

Configuration is stored in:

```text
config/sondar_config.json
```

| Setting | Purpose |
|---|---|
| `auto_detect_target` | Enables local IPv4 target detection using Windows interface data. |
| `confirm_target_before_scan` | Requires operator confirmation before scanning the suggested CIDR range. |
| `allow_manual_target` | Allows the operator to enter a manual CIDR range when auto-detection is wrong or rejected. |
| `fallback_target` | Optional backup target. It is intentionally empty by default so Sondar does not silently scan a hardcoded range. |
| `scan_mode` | Default scan profile shown during scan mode selection. The operator can override it for the current run. |
| `timeout_seconds` | Maximum scan execution time before the Nmap subprocess is allowed to time out. |

The configuration file stores defaults. Runtime prompts decide the actual target and scan profile for each run.

---

## Project Status

Current status: **working portfolio implementation**.

| Area | Status |
|---|---|
| Operator Menu | Implemented with Network Scan, Clear Artefacts, and Exit actions. |
| Launcher | Implemented through `sondar.bat` with Python and Nmap checks. |
| Target Detection | Implemented for Windows IPv4 interface output with manual CIDR override. |
| Scan Profiles | Implemented with discovery, basic, standard, and deep modes selected per run. |
| XML Parsing | Implemented for Nmap host, port, service, and run-statistics output. |
| Inventory | Implemented through timestamped JSON snapshots. |
| Change Detection | Implemented for host presence and service exposure changes. |
| Discovery Awareness | Implemented to avoid false port-change results when discovery scans are compared with port scans. |
| Reporting | Implemented through timestamped Markdown reports. |
| Artefact Cleanup | Implemented for runtime folders and Python cache directories. |

Future development could focus on friendly device labels, CSV inventory export, pinned baseline comparison, service exposure scoring, multi-adapter selection, richer CPE reporting, or HTML report output.

---

## Limitations

| Limitation | Explanation |
|---|---|
| Authorised Scope | Sondar is intended for networks the operator is authorised to scan. The workflow asks for target confirmation, but permission and scope remain the operator's responsibility. |
| Observed State | Results represent what Nmap observed during that scan. Firewalls, host configuration, network conditions, and scan profile selection can affect visibility. |
| Vulnerability Context | Sondar identifies exposed services and service changes. It does not confirm exploitability, validate vulnerabilities, perform credentialed checks, or attempt exploitation. |
| Discovery Data | Discovery scans do not collect port data. Sondar handles this by skipping port change comparison when one or more compared snapshots do not include port scan data. |
| Platform Focus | The current target detection logic is Windows-focused because it parses Windows interface output. Cross-platform interface detection would require additional platform-specific handling. |

---

## Licence

MIT License. See `LICENSE`.
