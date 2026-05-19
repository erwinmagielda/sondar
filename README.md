# Sondar

**Network visibility workflow for host discovery, service inventory, and change detection.**

Sondar is a Python-based network visibility tool for authorised home and lab environments. It detects a local network target, asks the operator to confirm or override it, runs a selected nmap scan profile, parses XML scan output, builds inventory snapshots, compares changes between runs, and generates Markdown reports.

The project addresses a practical monitoring problem:

> A home or lab network can change without obvious warning. New devices can appear, exposed services can change, and previous assumptions about open ports can become stale. Sondar turns repeated scans into structured evidence so those changes can be reviewed.

Sondar is designed for controlled, authorised environments. It is not an enterprise vulnerability scanner, intrusion detection system, or replacement for managed monitoring platforms.

---

## Overview

Sondar combines nmap-based collection with Python-based parsing, inventory creation, change detection, reporting, and operator control. The project demonstrates how raw network scan output can be converted into reviewable security artefacts without hiding the workflow behind a black box.

The project demonstrates:

- Local IPv4 target detection from Windows interface data.
- Operator confirmation before scanning.
- Manual CIDR target override.
- Per-run scan profile selection.
- nmap XML collection for repeatable parsing.
- Structured inventory snapshots in JSON.
- Host and port change detection between scans.
- Markdown report generation for review.
- Runtime artefact cleanup while preserving repository structure.
- A menu-driven Windows launcher for controlled operation.

---

## Screenshots

The screenshots below show Sondar running as an operator-facing workflow. They are included to demonstrate target confirmation, per-run scan profile selection, scan execution, parsed output, inventory generation, change detection, reporting, and artefact cleanup.

### Operator Menu

![Operator Menu](assets/operator_menu.png)

The operator menu provides a single entry point for running a network scan, clearing generated artefacts, or exiting the tool.

### Host Configuration

![Host Configuration](assets/host_configuration.png)

The workflow prepares runtime directories, initialises logging, and loads configuration before any scan is executed. Output paths are displayed as repository-relative paths to keep terminal output clean and reviewable.

### Scan Configuration

![Scan Configuration](assets/scan_configuration.png)

Sondar detects the local IPv4 network target, displays the adapter, address, subnet mask, and suggested CIDR range, then asks the operator to confirm or override the target. Scan mode selection is performed per run, allowing the operator to choose discovery, basic, standard, or deep scanning without permanently changing the configuration file.

### Scan Execution

![Scan Execution](assets/scan_execution.png)

The scan stage runs the selected nmap profile, saves raw XML output, parses host and service data, and prints a concise summary of live hosts and open ports.

### Change Detection

![Change Detection](assets/change_detection.png)

The inventory stage writes a structured JSON snapshot. Change detection compares the current inventory against the previous snapshot and reports new hosts, missing hosts, newly open ports, and closed ports.

### Clear Artefacts

![Clear Artefacts](assets/clearing_artefacts.png)

The cleanup workflow removes generated logs, scans, reports, inventory snapshots, and Python cache directories while preserving repository structure.

---

## Technical Capabilities

Sondar is built as a modular CLI workflow rather than a single scanning script. Each capability supports visibility, repeatability, or safer operator control.

| Area | Implementation |
|---|---|
| Core Stack | Python standard library, Windows batch launcher, and nmap as the external scan engine. |
| Target Handling | The tool detects local IPv4 interface data, calculates a suggested CIDR target, and requires operator confirmation or manual override. |
| Scan Profiles | Per-run scan profiles support discovery, basic, standard, and deep scanning without permanently editing the configuration file. |
| Scan Collection | nmap writes XML output to `data/scans/`, preserving raw scan evidence for later review. |
| Parsing | Python parses nmap XML into structured host, service, port, and run-statistics data. |
| Inventory | Parsed scan data is normalised into JSON inventory snapshots under `data/inventory/`. |
| Change Detection | Sondar compares inventory snapshots to identify new hosts, missing hosts, newly open ports, and closed ports. |
| Reporting | Markdown reports are generated under `data/reports/` for readable review and portfolio evidence. |
| Operational Control | The workflow uses an interactive menu, explicit scan confirmation, clean status markers, and a clear artefact cleanup mode. |
| Evidence Quality | Raw XML, inventory JSON, logs, and Markdown reports allow each stage of the workflow to be inspected independently. |

---

## Architecture

The architecture separates target detection, scan execution, parsing, inventory creation, change detection, reporting, logging, and cleanup. This makes the project easier to inspect, test, and explain.

```text
sondar.bat
│   Launches the interactive operator menu from the repository root.
│   Checks that Python and nmap are available before starting.
│
config/
│   └── sondar_config.json
│       Stores safe default behaviour such as target handling,
│       default scan mode, timeout, and scan profile descriptions.
│
data/
├── scans/
│   Stores raw nmap XML scan artefacts.
│
├── inventory/
│   Stores normalised JSON inventory snapshots.
│
├── reports/
│   Stores generated Markdown scan reports.
│
├── logs/
│   Stores timestamped runtime logs.
│
src/
├── sondar_main.py
│   Provides the menu, workflow orchestration, target confirmation,
│   per-run scan mode selection, and stage-level terminal output.
│
├── core/
│   ├── sondar_network.py
│   │   Detects local IPv4 interface data and calculates a suggested CIDR target.
│   │
│   ├── sondar_scanner.py
│   │   Builds and runs nmap commands based on the selected scan profile.
│   │
│   ├── sondar_parser.py
│   │   Parses nmap XML into structured Python dictionaries.
│   │
│   ├── sondar_inventory.py
│   │   Builds normalised JSON inventory snapshots from parsed scan data.
│   │
│   ├── sondar_detector.py
│   │   Compares inventory snapshots and reports host or port changes.
│   │
│   ├── sondar_reporter.py
│   │   Generates Markdown reports from scan, inventory, and change data.
│   │
│   └── sondar_artefacts.py
│       Clears generated runtime artefacts while preserving repository structure.
│
└── utils/
    ├── sondar_banner.py
    │   Provides the ASCII logo, headers, sections, and status marker output.
    │
    ├── sondar_logger.py
    │   Creates timestamped runtime logs.
    │
    └── sondar_paths.py
        Centralises repository paths and clean relative path output.
```

Each stage passes structured data to the next stage. Raw nmap XML is preserved as evidence, while JSON inventory snapshots and Markdown reports make the results easier to review.

---

## Workflow

Sondar follows a staged workflow:

```text
Operator Menu
    -> Network Scan
    -> Prepare Paths
    -> Load Configuration
    -> Detect Target
    -> Confirm or Override Target
    -> Select Scan Mode for This Run
    -> Run nmap
    -> Save Raw XML
    -> Parse XML
    -> Build Inventory Snapshot
    -> Detect Changes
    -> Write Markdown Report
```

This structure keeps the scan process explicit. The operator can see what target will be scanned, which scan profile will be used, where artefacts are saved, and what changed compared with previous inventory data.

---

## Scan Profiles

Sondar supports scan profiles selected at runtime. The default mode is stored in `config/sondar_config.json`, but each scan asks the operator to choose the mode for that run.

| Mode | nmap Behaviour | Purpose |
|---|---|---|
| `discovery` | `nmap -sn` | Identifies live hosts without port scanning. |
| `basic` | `nmap -sV --top-ports 100` | Fast service snapshot using common TCP ports. |
| `standard` | `nmap -sV --top-ports 1000` | Broader service snapshot with better port coverage. |
| `deep` | `nmap -sV -p-` | Full TCP port range service scan for authorised deeper review. |

Discovery scans do not collect port data. Sondar tracks this in the inventory metadata so change detection does not falsely report ports as closed when comparing a port scan against a discovery scan.

---

## Output Artefacts

Sondar writes reviewable artefacts into the `data/` directory.

| Artefact | Location | Purpose |
|---|---|---|
| Raw nmap XML | `data/scans/` | Preserves original scan output for evidence and re-parsing. |
| Inventory JSON | `data/inventory/` | Stores normalised host and service state for comparison. |
| Markdown Report | `data/reports/` | Provides readable scan and change detection output. |
| Runtime Logs | `data/logs/` | Stores timestamped workflow details for troubleshooting. |

Generated files are ignored by Git. Empty runtime directories are preserved with `.gitkeep` files so the repository structure remains visible after cloning.

---

## Change Detection

Sondar compares the current inventory snapshot against the previous snapshot. It reports:

- New hosts.
- Missing hosts.
- Newly open ports.
- Closed ports.

Port change comparison only runs when both snapshots contain port scan data. For example, comparing `basic` to `discovery` will still compare host presence, but port changes are skipped because discovery mode does not collect port data.

Example report behaviour:

```text
New Hosts: 0
Missing Hosts: 0
New Open Ports: 0
Closed Ports: 0
Port Change Comparison: Skipped
```

This avoids misleading results when the scan profile changes between runs.

---

## Operation

Run the Windows launcher from the repository root:

```bat
sondar.bat
```

The launcher checks that Python and nmap are available in PATH before opening the operator menu.

```text
1) Network Scan
2) Clear Artefacts
3) Exit
```

### Network Scan

Network Scan detects the local target, asks for confirmation, allows manual CIDR override, asks which scan mode should be used for the current run, runs nmap, parses the result, creates an inventory snapshot, compares changes, and writes a Markdown report.

### Clear Artefacts

Clear Artefacts removes generated runtime files from:

```text
data/logs/
data/scans/
data/reports/
data/inventory/
```

It also removes Python `__pycache__` directories. Repository placeholder files such as `.gitkeep` are preserved.

### Direct Command Usage

The menu is the intended operator workflow, but direct commands are also supported:

```bat
python src\sondar_main.py --scan
python src\sondar_main.py --clear-artefacts
```

---

## Setup

Sondar currently uses Python standard-library modules only. No Python packages need to be installed with pip.

External dependency:

```text
nmap
```

nmap must be installed and available in PATH.

Check availability:

```bat
python --version
nmap --version
```

Then launch:

```bat
sondar.bat
```

---

## Configuration

The configuration file stores safe default behaviour:

```text
config/sondar_config.json
```

Example scan settings:

```json
{
    "scan": {
        "auto_detect_target": true,
        "confirm_target_before_scan": true,
        "allow_manual_target": true,
        "fallback_target": "",
        "scan_mode": "basic",
        "timeout_seconds": 300
    }
}
```

The config does not permanently decide every run. The default scan mode is shown during Network Scan, but the operator selects the scan profile for that specific run.

Target handling is intentionally explicit:

```text
Auto-detect local target
    -> Show detected interface details
    -> Ask for confirmation
    -> Allow manual CIDR override
    -> Scan only the selected target
```

---

## Project Structure

```text
Sondar/
├── README.md
├── requirements.txt
├── sondar.bat
├── config/
│   └── sondar_config.json
├── data/
│   ├── inventory/
│   │   └── .gitkeep
│   ├── logs/
│   │   └── .gitkeep
│   ├── reports/
│   │   └── .gitkeep
│   └── scans/
│       └── .gitkeep
├── src/
│   ├── sondar_main.py
│   ├── core/
│   │   ├── sondar_artefacts.py
│   │   ├── sondar_detector.py
│   │   ├── sondar_inventory.py
│   │   ├── sondar_network.py
│   │   ├── sondar_parser.py
│   │   ├── sondar_reporter.py
│   │   └── sondar_scanner.py
│   └── utils/
│       ├── sondar_banner.py
│       ├── sondar_logger.py
│       └── sondar_paths.py
└── assets/
    └── screenshots used by this README
```

---

## Technical Method

Sondar uses nmap as the scan engine because nmap already provides mature host discovery, port scanning, service detection, and XML output. Sondar focuses on the workflow around that collection engine:

```text
nmap
    -> Mature network probing and XML output

Sondar
    -> Target confirmation
    -> Per-run scan profile selection
    -> XML parsing
    -> Inventory generation
    -> Change detection
    -> Markdown reporting
    -> Artefact cleanup
```

The parser uses Python's XML standard library to extract host, port, service, run statistics, and metadata from nmap XML. The inventory module then normalises that parsed data into a stable JSON snapshot. The detector compares inventory snapshots rather than raw terminal output, which makes the workflow more repeatable and easier to review.

---

## Limitations

Sondar only scans authorised networks selected by the operator. It does not attempt stealth scanning, exploitation, credentialed checks, packet capture, or vulnerability validation.

The tool reports observed host and service state from nmap output. It does not prove whether a service is vulnerable, exploitable, or intentionally exposed.

Discovery scans do not collect port data. Sondar handles this by skipping port change comparison when one or more compared snapshots did not include port scan data.

Scan results depend on network conditions, host firewalls, adapter selection, nmap behaviour, and the selected scan profile. A filtered or non-responsive host may not appear the same way across different environments.

The project is intended as a home lab and portfolio tool. It is not a replacement for enterprise asset management, vulnerability management, EDR, SIEM, or managed network monitoring.

---

## Skills Demonstrated

Sondar demonstrates practical skills relevant to IT support, network operations, and junior cybersecurity work:

- Python CLI workflow design.
- Windows batch launcher creation.
- nmap integration through subprocess.
- XML parsing and structured data transformation.
- JSON inventory generation.
- Network target validation and CIDR handling.
- Host and port change detection logic.
- Operator safety through confirmation prompts.
- Runtime artefact management.
- Markdown report generation.
- Modular project structure and maintainable code organisation.
- Clear terminal output using consistent operational status markers.

---

## Project Status

Current status: **working portfolio implementation**.

Implemented functionality includes:

- Interactive operator menu.
- Windows launcher with Python and nmap checks.
- Local IPv4 target detection.
- Manual target override.
- Per-run scan mode selection.
- nmap XML scan execution.
- XML parsing into structured data.
- JSON inventory snapshots.
- Host and port change detection.
- Discovery-aware port comparison logic.
- Markdown report generation.
- Runtime artefact cleanup.
- Python cache cleanup.
- Repository-relative output paths.

Future development could focus on:

- Friendly device labels for known hosts.
- Exporting a current inventory summary as CSV.
- Optional service exposure scoring.
- Optional comparison against a pinned baseline rather than latest previous scan.
- Better multi-adapter selection when several active interfaces exist.
- More detailed report sections for CPEs and service confidence.
- Optional dashboard or HTML report view.

---

## Licence

MIT License. See `LICENSE`.
