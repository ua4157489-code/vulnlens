# 🔍 VulnLens

**Aggregate, normalize and report vulnerability scan results from multiple tools: one format, one workflow.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
[![CI](https://github.com/ua4157489-code/vulnlens/actions/workflows/ci.yml/badge.svg)](https://github.com/ua4157489-code/vulnlens/actions)

> ⚠️ **Responsible use:** VulnLens only *analyzes scan output you already have*. Only scan and assess systems you own or have explicit written permission to test.

---

## Why VulnLens?

Every scanner has its own output format. Nmap speaks one XML dialect, OpenVAS another, ZAP uses JSON. Comparing them, tracking fixes and writing a report means a lot of copy-pasting.

VulnLens parses each tool's output into **one normalized data model**, so you can filter, score, map to OWASP Top 10 / CWE, and export consistently.

## Features (v0.1)

- ✅ Parsers for **Nmap XML** (`-oX`) and **OpenVAS / Greenbone XML** reports
- ✅ Auto-detection of input format
- ✅ Unified `Finding` model with severity, CVSS, CVEs, remediation and stable IDs
- ✅ Severity filtering (`--min-severity`)
- ✅ Terminal summary and **JSON export**
- ✅ **Safe XML parsing** via `defusedxml` (blocks XXE and entity-expansion attacks)
- ✅ Unit-tested, CI-ready, zero-config

## Installation

```bash
git clone https://github.com/ua4157489-code/vulnlens.git
cd vulnlens
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
# Summary in the terminal (format is auto-detected)
vulnlens parse scan.xml

# Only show High and Critical findings
vulnlens parse openvas_report.xml --min-severity high

# Export normalized JSON
vulnlens parse nmap_scan.xml -o results.json

# Force a format
vulnlens parse report.xml --format openvas
```

Example output:

```
Source  : openvas
Assets  : 2
Findings: 3

By severity:
  Critical 1
  High     0
  Medium   1
  Low      0
  Info     1

Top 3 findings:
  [Critical] Remote Code Execution in Example Service @ 192.168.56.101:8080 (CVSS 9.8)
  [Medium  ] Weak SSL/TLS Protocol Versions Supported @ 192.168.56.101:443 (CVSS 4.3)
  [Info    ] TCP Timestamps @ 192.168.56.103
```

A full JSON example lives in [`examples/sample_report.json`](examples/sample_report.json).

## Generating scan files to test with

Use a lab target you own (e.g. a local OWASP Juice Shop container or an intentionally vulnerable VM):

```bash
nmap -sV --script vuln -oX nmap_scan.xml <your-lab-target>
```

For OpenVAS/Greenbone, export a report as **XML** from the web UI (Scans → Reports → Download).

## Project structure

```
vulnlens/
├── vulnlens/
│   ├── cli.py            # Command-line interface
│   ├── core/models.py    # Severity, Finding, Asset, ScanResult
│   ├── collectors/       # One parser per scanner (Nmap, OpenVAS)
│   └── reporting/        # JSON + terminal output
├── tests/                # Unit tests + sample scan files
├── docs/architecture.md  # Design notes and how to add a collector
└── examples/             # Sample output
```

See [docs/architecture.md](docs/architecture.md) for design details.

## Roadmap

- [x] **v0.1**: Nmap + OpenVAS parsers, normalized model, JSON export
- [ ] **v0.2**: OWASP Top 10 + CWE mapping, risk scoring
- [ ] **v0.3**: HTML / Markdown report generator
- [ ] **v0.4**: OWASP ZAP parser, passive web checks (headers, cookies, TLS)
- [ ] **v0.5**: SQLite history and scan-to-scan diffing
- [ ] **v1.0**: Plugin system, PyPI release

## Running tests

```bash
pytest          # or: python -m unittest discover -s tests -t .
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue in VulnLens itself, see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
