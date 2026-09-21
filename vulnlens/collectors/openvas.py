"""Parser for OpenVAS / Greenbone (GVM) XML reports."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Tuple

from vulnlens.collectors.base import Collector, load_xml
from vulnlens.core.models import Asset, Finding, ScanResult, Severity

_PORT_RE = re.compile(r"^(?P<port>\d+)/(?P<proto>\w+)$")


def _text(el, path: str, default: str = "") -> str:
    """Stripped text of a child element, or ``default`` if missing/empty."""
    if el is None:
        return default
    found = el.find(path)
    if found is None or not found.text:
        return default
    return found.text.strip()


def _parse_port(value: str) -> Tuple[Optional[int], Optional[str]]:
    match = _PORT_RE.match(value.strip())
    if match:
        return int(match.group("port")), match.group("proto").lower()
    return None, None  # e.g. "general/tcp"


def _to_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class OpenVASCollector(Collector):
    name = "openvas"

    def matches(self, root_tag: str) -> bool:
        return root_tag in {"report", "get_reports_response"}

    def parse(self, path: Path) -> ScanResult:
        root = load_xml(path)
        result = ScanResult(source=self.name)
        seen_hosts = set()

        # GVM nests <report><report><results>; iterating all <result> handles both layouts.
        for res in root.iter("result"):
            host_el = res.find("host")
            address = (host_el.text or "").strip() if host_el is not None else ""
            if not address:
                continue
            if address not in seen_hosts:
                seen_hosts.add(address)
                hostname = _text(host_el, "hostname")
                result.assets.append(
                    Asset(address=address, hostnames=[hostname] if hostname else [])
                )

            port, proto = _parse_port(_text(res, "port"))
            nvt = res.find("nvt")
            cvss = _to_float(_text(res, "severity"))
            if not cvss:
                cvss = _to_float(_text(nvt, "cvss_base"))
            severity = (
                Severity.from_cvss(cvss) if cvss else Severity.from_name(_text(res, "threat"))
            )

            cves, refs = [], []
            if nvt is not None:
                for ref in nvt.findall("refs/ref"):
                    ref_type, ref_id = ref.get("type", "").lower(), ref.get("id", "")
                    if ref_type == "cve":
                        cves.append(ref_id)
                    elif ref_id:
                        refs.append(ref_id)

            result.findings.append(
                Finding(
                    title=_text(res, "name") or _text(nvt, "name") or "Unnamed finding",
                    severity=severity,
                    source=self.name,
                    host=address,
                    port=port,
                    protocol=proto,
                    cvss=cvss,
                    description=_text(res, "description"),
                    solution=_text(nvt, "solution"),
                    cves=sorted(set(cves)),
                    references=sorted(set(refs)),
                )
            )
        return result
