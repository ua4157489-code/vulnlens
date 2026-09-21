"""Parser for Nmap XML output (``nmap -oX``)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from vulnlens.collectors.base import Collector, load_xml
from vulnlens.core.models import Asset, Finding, ScanResult, Severity


class NmapCollector(Collector):
    name = "nmap"

    def matches(self, root_tag: str) -> bool:
        return root_tag == "nmaprun"

    def parse(self, path: Path) -> ScanResult:
        root = load_xml(path)
        result = ScanResult(
            source=self.name,
            metadata={
                "scanner": root.get("scanner", "nmap"),
                "version": root.get("version", ""),
                "args": root.get("args", ""),
            },
        )

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            if addr_el is None:
                continue
            address = addr_el.get("addr", "")
            hostnames = [h.get("name", "") for h in host.findall("hostnames/hostname")]
            os_el = host.find("os/osmatch")
            result.assets.append(
                Asset(
                    address=address,
                    hostnames=[h for h in hostnames if h],
                    os=os_el.get("name") if os_el is not None else None,
                )
            )

            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                result.findings.extend(self._port_findings(address, port))

        return result

    def _port_findings(self, address: str, port) -> List[Finding]:
        portid = int(port.get("portid", "0"))
        proto = port.get("protocol", "tcp")
        svc = port.find("service")
        svc_name = "unknown"
        product = ""
        if svc is not None:
            svc_name = svc.get("name", "unknown")
            product = " ".join(p for p in (svc.get("product"), svc.get("version")) if p)

        findings = [
            Finding(
                title=f"Open port {portid}/{proto} ({svc_name})",
                severity=Severity.INFO,
                source=self.name,
                host=address,
                port=portid,
                protocol=proto,
                description=(
                    f"Service '{svc_name}' is reachable"
                    + (f" running {product}." if product else ".")
                ),
                solution="Confirm the service is required; close or firewall it otherwise.",
            )
        ]

        # NSE scripts that explicitly report a vulnerable state become findings.
        for script in port.findall("script"):
            output = script.get("output", "")
            upper = output.upper()
            if "VULNERABLE" in upper and "NOT VULNERABLE" not in upper:
                findings.append(
                    Finding(
                        title=f"NSE script '{script.get('id', 'unknown')}' reports vulnerable",
                        severity=Severity.HIGH,
                        source=self.name,
                        host=address,
                        port=portid,
                        protocol=proto,
                        description=output.strip(),
                        solution="Review the script output and apply vendor patches.",
                    )
                )
        return findings
