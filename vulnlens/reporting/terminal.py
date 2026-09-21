"""Plain-text terminal summary (no third-party dependencies)."""

from __future__ import annotations

from vulnlens.core.models import ScanResult


def render_summary(result: ScanResult, top: int = 10) -> str:
    lines = [
        f"Source  : {result.source}",
        f"Assets  : {len(result.assets)}",
        f"Findings: {len(result.findings)}",
        "",
        "By severity:",
    ]
    for label, count in result.counts_by_severity().items():
        lines.append(f"  {label:<9}{count}")

    findings = result.sorted_findings()[:top]
    if findings:
        lines += ["", f"Top {len(findings)} findings:"]
        for f in findings:
            where = f.host + (f":{f.port}" if f.port else "")
            score = f" (CVSS {f.cvss})" if f.cvss else ""
            lines.append(f"  [{f.severity.label():<8}] {f.title} @ {where}{score}")
    return "\n".join(lines)
