# AD-AuthGraph — User Guide

A complete instruction document for using AD-AuthGraph efficiently.

---

## What is AD-AuthGraph?

AD-AuthGraph is a four-stage security analysis pipeline for Active Directory environments. It takes a raw AD state snapshot and produces an interactive HTML report that surfaces:

- Privilege escalation paths to Domain Admins
- ACL abuse chains (dangerous explicit permissions)
- Kerberoastable identities (accounts with SPNs)
- Delegation misconfigurations

---

## Pipeline Overview

The tool runs in four sequential stages, all automated by `main.py`:

```
Stage 1  graph_builder.py   →  <stem>_graph.json
Stage 2  analyzer.py        →  <stem>_analysis.json
Stage 3  refiner.py         →  <stem>_refined.json
Stage 4  visualizer.py      →  <stem>_report_refined.html
```

All output filenames are derived from the input filename stem.
Example: input `blues_state.json` → outputs `blues_state_graph.json`, `blues_state_analysis.json`, etc.

---

## Prerequisites

### Collector machine (Windows, domain-joined)
- PowerShell 5.1 or later
- ActiveDirectory module:
  ```powershell
  # Windows Server
  Install-WindowsFeature RSAT-AD-PowerShell

  # Windows 10/11
  # Enable via Settings → Optional Features → RSAT: Active Directory
  ```
- Domain read permissions (Domain Admin not required, but improves ACL coverage)
- Execution policy allowing scripts:
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

### Analysis machine (any OS with Python)
- Python 3.9+
- NetworkX (required):
  ```
  pip install networkx
  ```
- matplotlib (optional, for static PNG graph export):
  ```
  pip install matplotlib
  ```

---

## Step 1 — Collect AD State (PowerShell)

Run the collector on a domain-joined Windows machine.

### Basic usage
```powershell
.\Collect-ADAuthorizationState.ps1
```
Writes output to `ad_authorization_state.json` in the current directory.

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputFile <path>` | Path for the output JSON file | `ad_authorization_state.json` |
| `-Domain <FQDN>` | Target domain FQDN | Current user's domain |
| `-IncludeBuiltIn $true/$false` | Include built-in groups (Administrators, Backup Operators, etc.) | `$true` |

### Examples

```powershell
# Custom output filename
.\Collect-ADAuthorizationState.ps1 -OutputFile "snapshot_jan2026.json"

# Target a specific domain
.\Collect-ADAuthorizationState.ps1 -Domain "child.corp.local" -OutputFile "child.json"

# Exclude built-in groups (smaller output, faster)
.\Collect-ADAuthorizationState.ps1 -IncludeBuiltIn $false
```

### Notes
- ACL collection is the slowest phase. On large domains (10,000+ objects) expect 30–60 minutes.
- The script prints a progress counter every 10 objects during ACL collection.
- Objects the collector cannot read are skipped with a warning (does not abort the run).

---

## Step 2 — Run the Analysis Pipeline (Python)

Copy the JSON file to your analysis machine, then run `main.py`.

### Basic usage
```
python main.py ad_authorization_state.json
```
This is the only command most users need. Runs all four stages and produces the HTML report.

### CLI flags

| Flag | Description |
|------|-------------|
| `input_file` | Path to the JSON from the PowerShell collector. Required. |
| `--output DIR` / `-o DIR` | Write all output files to DIR instead of the input file's directory. |
| `--no-graph-png` | Skip the optional matplotlib PNG export. Faster; no matplotlib needed. |
| `--quiet` / `-q` | Suppress all console progress output. Exit code still reflects success/failure. |
| `--compare CURRENT PREVIOUS` | Compare two AD state snapshots instead of running the full pipeline. |

### Examples

```bash
# Full pipeline, default output location
python main.py ad_authorization_state.json

# Write all outputs to a dedicated folder
python main.py ad_authorization_state.json --output ./reports

# Skip PNG export (recommended if matplotlib is not installed)
python main.py ad_authorization_state.json --no-graph-png

# Quiet mode for scripted/CI use
python main.py ad_authorization_state.json --quiet

# Compare two snapshots (change detection)
python main.py --compare current_state.json previous_state.json

# Compare with custom output folder
python main.py --compare current_state.json previous_state.json --output ./deltas
```

---

## Output Files

| File | Description |
|------|-------------|
| `<stem>_graph.json` | Directed authorization graph (nodes + edges). Input to the analyzer. |
| `<stem>_analysis.json` | Raw findings: DA paths, Kerberoastable identities, ACL chains, delegation risks. |
| `<stem>_refined.json` | Enriched findings with OU context, privilege proximity. |
| `<stem>_report_refined.html` | **The interactive HTML report. Open this in any browser.** |
| `<stem>_graph.png` | (Optional) Static graph PNG. Only produced when matplotlib is installed and `--no-graph-png` is not set. |
| `state_comparison.json` | (Compare mode only) Delta between two AD snapshots. |

---

## Reading the HTML Report

Open `<stem>_report_refined.html` directly in Chrome, Firefox, or Edge. No web server or internet connection required.

### Sections

**Executive Summary** — KPI tiles showing total ACL findings, DA path count, Kerberoastable count, delegation risks. Includes a ranked table of the top exploitable chains.

**ACL Abuse Chains** — Each entry shows the full escalation path, permission type, source/target privilege proximity, and authorities gained.

**Domain Admin Privilege Paths** — Every identity with a graph path to Domain Admins, with hop count and total path count.

**Kerberoastable Identities** — Accounts with SPNs, their risk level, DA path count, and registered SPNs.

**Delegation Risks** — Delegation configurations with type (unconstrained/constrained/RBCD), conditions, and risk level.

**Graph Explorer** — Interactive force-directed graph. Drag nodes, scroll to zoom, drag empty canvas to pan, hover for details. Use the Reset View button to restore the initial layout.

### Privilege proximity
Shortest graph-path distance from an identity to a Tier-0 group (Domain Admins, Enterprise Admins, Administrators, etc.). 0 = IS Tier-0. 1 = direct member of Tier-0. Higher = more hops required.

---

## Running Individual Scripts

Each stage can be run independently — useful for partial re-runs or debugging.

### graph_builder.py
```bash
python graph_builder.py <ad_state_json>

# Example:
python graph_builder.py ad_authorization_state.json
# Produces: ad_authorization_state_graph.json
```

### analyzer.py
```bash
# Standard (takes graph JSON):
python analyzer.py <graph_json>

# Example:
python analyzer.py ad_authorization_state_graph.json

# Compare two graph JSONs directly:
python analyzer.py current_graph.json --compare previous_graph.json

# Backward-compatibility mode (takes raw AD JSON):
python analyzer.py ad_authorization_state.json --raw
```

### refiner.py
```bash
python refiner.py <analysis_json> [<graph_json>] [--output <path>]

# Graph JSON is auto-detected if omitted (replaces _analysis.json with _graph.json):
python refiner.py ad_authorization_state_analysis.json

# Explicit graph path:
python refiner.py ad_authorization_state_analysis.json ad_authorization_state_graph.json

# Custom output path:
python refiner.py ad_authorization_state_analysis.json --output my_refined.json
```

### visualizer.py
```bash
python visualizer.py <refined_json>

# Example:
python visualizer.py ad_authorization_state_refined.json
# Produces: ad_authorization_state_report_refined.html
```

---

## Comparison Mode (Change Detection)

Use this to detect new privilege escalation paths between two AD snapshots.

```bash
python main.py --compare current_state.json previous_state.json
```

### What the comparison reports
- DA path count, edge count, and Kerberoastable count for both states
- Numeric deltas for each metric (e.g. `+3 DA paths`)
- New DA paths — identities that gained access to Domain Admins since the previous snapshot
- Removed DA paths — identities whose DA path was remediated
- New Kerberoastable accounts — accounts that acquired SPNs since the last snapshot

Output is printed to the console and saved as `state_comparison.json`.

---

## Recommended Workflow

### First run
```powershell
# 1. On the domain-joined Windows machine:
.\Collect-ADAuthorizationState.ps1 -OutputFile snapshot_week1.json
```

```bash
# 2. On your analysis machine:
pip install networkx
python main.py snapshot_week1.json --output ./reports
# Open: ./reports/snapshot_week1_report_refined.html
```

### Recurring audit (weekly/monthly)
```powershell
# Collect a fresh snapshot:
.\Collect-ADAuthorizationState.ps1 -OutputFile snapshot_week2.json
```

```bash
# Run the full pipeline on the new snapshot:
python main.py snapshot_week2.json --output ./reports

# Compare against the previous to find what changed:
python main.py --compare snapshot_week2.json snapshot_week1.json --output ./deltas
```

---

## Troubleshooting

**ActiveDirectory module not found**
```powershell
Install-WindowsFeature RSAT-AD-PowerShell          # Windows Server
# or via Settings → Optional Features on Windows 10/11
```

**Execution policy error**
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# or launch with: powershell -ExecutionPolicy Bypass
```

**ModuleNotFoundError: networkx**
```
pip install networkx
```

**"Domain Admins group not found in graph" warning**
The Domain Admins group was not collected. Ensure `-IncludeBuiltIn $true` (the default) is set when running the collector. DA path analysis will return empty results without it.

**matplotlib not available — PNG skipped**
This is informational, not an error. Install with `pip install matplotlib` to enable, or use `--no-graph-png` to suppress the message.

**HTML report opens blank**
Open in Chrome or Firefox. Some browsers restrict local file JavaScript. If opening from a network share, copy the file to a local drive first.

**ACL collection is very slow**
Expected on large domains. The script prints progress every 10 objects. You can exclude built-in groups with `-IncludeBuiltIn $false` to reduce scope slightly. There is no way to skip ACL collection entirely while still detecting ACL abuse chains.
