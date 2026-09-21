# Security Policy

## Reporting a vulnerability in VulnLens

Please **do not open a public issue** for security problems. Instead, report privately using
GitHub's "Report a vulnerability" feature on the Security tab, or email the maintainer.

Include steps to reproduce, affected versions, and the potential impact. You can expect an
acknowledgement within a few days.

## Design notes

- Scan files are treated as **untrusted input**. XML is parsed with `defusedxml` to block XXE and
  entity-expansion attacks.
- VulnLens only analyzes existing scan output; it does not perform scans or exploitation.

## Responsible use

Only assess systems you own or have explicit written authorization to test.
