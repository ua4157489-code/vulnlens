# Architecture

```
scan file (XML) ──► Collector ──► ScanResult ──► Reporter
                    (per tool)    (normalized)   (JSON / terminal / later HTML)
```

## Core model (`vulnlens/core/models.py`)

| Type | Purpose |
|------|---------|
| `Severity` | Ordered enum: Info < Low < Medium < High < Critical. Built from CVSS score or a label. |
| `Asset` | A scanned host (address, hostnames, OS). |
| `Finding` | One issue: title, severity, host/port, CVSS, CVEs, CWEs, OWASP categories, remediation. Has a **stable ID** (hash of source + host + port + title) for tracking across scans. |
| `ScanResult` | Assets + findings + metadata from one file, with filtering and summary helpers. |

## Collectors (`vulnlens/collectors/`)

Each collector implements two methods:

- `matches(root_tag)`: used for format auto-detection
- `parse(path)`: returns a `ScanResult`

All XML is loaded through `load_xml()`, which uses `defusedxml` so malicious scan files cannot
trigger XXE or entity-expansion attacks.

## Severity mapping

- **OpenVAS**: uses the result's CVSS severity; falls back to the threat label.
- **Nmap**: open ports are `Info`. NSE scripts whose output reports a vulnerable state (and not
  "NOT VULNERABLE") are `High`. This is a heuristic, so review the raw script output.

## Planned

- `mapping/`: OWASP Top 10 and CWE lookups (populates `Finding.owasp` / `Finding.cwes`)
- `scoring.py`: composite risk score per asset
- `reporting/html.py`: Jinja2 report
- `storage/`: SQLite history and diffing using the stable finding IDs
