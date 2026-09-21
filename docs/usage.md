# Usage guide

## Parse a scan

```bash
vulnlens parse <scan-file>
```

VulnLens detects whether the file is Nmap XML or OpenVAS/Greenbone XML automatically.

## Options

| Option | Purpose |
|---|---|
| `--min-severity LEVEL` | Show only findings at or above `info`, `low`, `medium`, `high` or `critical` |
| `-o FILE` | Write normalized findings to a JSON file |
| `--help` | Show all options |

## Examples

```bash
# Bundled sample: 1 Critical, 1 Medium, 1 Info across 2 assets
vulnlens parse tests/data/sample_openvas.xml

# Scan your own lab with Nmap, then parse the result
nmap -sV --script vuln -p 22,80,443,3000,8080 -oX scans/nmap_lab.xml 127.0.0.1
vulnlens parse scans/nmap_lab.xml

# Filter and export
vulnlens parse scans/nmap_lab.xml --min-severity low
vulnlens parse scans/nmap_lab.xml -o scans/nmap_lab.json
```

## Safety notes

- Only scan systems you own or have written permission to test.
- Scan files can contain hostnames and IPs. Keep real ones out of Git (the `scans/` folder is ignored by default).
