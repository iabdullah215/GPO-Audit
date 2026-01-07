# GPO-Audit

GPO-Audit audits Microsoft Group Policy Object (GPO) reports exported via `Get-GPOReport` (HTML or XML). It focuses on identifying common hardening gaps, risky delegation, and unresolved (orphaned) security principals, and it can export results and compare drift against a baseline.

This repository includes:
- [gpoaudit.py](gpoaudit.py) (Python)
- [gpoaudit.ps1](gpoaudit.ps1) (PowerShell 7+)

## Key Features

- Structured findings with severities: `CRITICAL`, `HIGH`, `MED`, `INFO`
- Step 2 (SIDs): reports ghost/unresolved SIDs with nearby context (XML structured when available)
- Step 4 (Delegation): flags risky trustees and write-level permissions
- Explicit CRITICAL detection for orphaned SIDs with administrative delegation ("Orphaned Security Principal with Administrative Control")
- Optional exports: JSON and CSV
- Optional baseline drift comparison: identify new vs resolved findings

## Requirements

### Python

- Python 3.10+ recommended
- Dependencies: `beautifulsoup4`, `colorama`

Install dependencies:

```bash
python3 -m pip install beautifulsoup4 colorama
```

### PowerShell

- PowerShell 7+ (`pwsh`)

## Generating Input Reports

Generate reports from a Windows/domain environment where the Group Policy module is available:

```powershell
Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Xml  -Path .\gpo.xml
Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Html -Path .\gpo.html
```

XML is recommended when possible because it enables more structured parsing.

## Quick Start (Recommended Workflow)

1) Export an XML report and treat it as a baseline:

```powershell
Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Xml -Path .\baseline.xml
```

2) Run the audit and export machine-readable outputs:

```bash
python3 gpoaudit.py --xml baseline.xml --json-out baseline.json --csv-out baseline.csv
```

3) Later, export a fresh report and compare drift:

```powershell
Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Xml -Path .\current.xml
```

```bash
python3 gpoaudit.py --xml current.xml --baseline baseline.json --json-out current.json --csv-out current.csv
```

The tool prints a drift summary showing new and resolved findings.

## Usage

### Python

```bash
python3 gpoaudit.py --xml report.xml
python3 gpoaudit.py --html report.html

python3 gpoaudit.py --xml report.xml --json-out out.json --csv-out out.csv
python3 gpoaudit.py --xml report.xml --baseline baseline.json
```

### PowerShell

```powershell
pwsh ./gpoaudit.ps1 -Xml .\report.xml
pwsh ./gpoaudit.ps1 -Html .\report.html

pwsh ./gpoaudit.ps1 -Xml .\report.xml -JsonOut .\out.json -CsvOut .\out.csv
pwsh ./gpoaudit.ps1 -Xml .\report.xml -Baseline .\baseline.json
```

## Output Formats

### JSON

The JSON export contains:

- `generated_at`: UTC timestamp
- `summary`: severity counts and totals
- `reports[]`: one entry per input file
  - `metadata`: best-effort GPO metadata
  - `findings[]`: structured findings with `level`, `category`, `title`, `message`, `context`, and source identifiers

### CSV

CSV exports one row per finding with these columns:

- `gpo_name`, `source`, `input_file`, `level`, `category`, `title`, `message`, `context`

## Interpreting Critical Delegation Findings

The CRITICAL finding titled "Orphaned Security Principal with Administrative Control" indicates an unresolved SID is granted write/admin-level GPO delegation (for example, "Edit settings, delete, modify security"). This is high risk because it can represent leftover access for a deleted principal.

## Notes and Limitations

- HTML parsing is best-effort and varies across Windows versions and export formats.
- XML parsing is tuned to Microsoft `Get-GPOReport` structures such as `SecurityOptions`, `UserRightsAssignment`, and `TrusteePermissions`.
- Results should be validated against authoritative sources (e.g., AD objects, GPO permissions) before remediation.
