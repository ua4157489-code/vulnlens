"""Normalized data models shared by every collector and reporter."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class Severity(IntEnum):
    """Ordered severity levels (higher value = more severe)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        """Map a CVSS v3-style base score to a severity rating."""
        if score is None or score <= 0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Parse a severity label such as 'High', 'log' or 'critical'."""
        key = (name or "").strip().upper()
        aliases = {"LOG": "INFO", "NONE": "INFO", "INFORMATIONAL": "INFO", "FALSE POSITIVE": "INFO"}
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError:
            return cls.INFO

    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Asset:
    """A scanned host."""

    address: str
    hostnames: List[str] = field(default_factory=list)
    os: Optional[str] = None


@dataclass
class Finding:
    """A single normalized finding, regardless of which tool produced it."""

    title: str
    severity: Severity
    source: str
    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    cvss: Optional[float] = None
    description: str = ""
    solution: str = ""
    cves: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Stable ID so the same issue can be tracked across scans."""
        raw = "|".join(
            [self.source, self.host, str(self.port or ""), self.protocol or "", self.title]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["severity"] = self.severity.label()
        data["id"] = self.id
        return data


@dataclass
class ScanResult:
    """All assets and findings parsed from one scan file."""

    source: str
    assets: List[Asset] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def filter_min_severity(self, minimum: Severity) -> "ScanResult":
        return ScanResult(
            source=self.source,
            assets=self.assets,
            findings=[f for f in self.findings if f.severity >= minimum],
            metadata=self.metadata,
        )

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {sev.label(): 0 for sev in sorted(Severity, reverse=True)}
        for finding in self.findings:
            counts[finding.severity.label()] += 1
        return counts

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), -(f.cvss or 0), f.host))

    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "metadata": self.metadata,
            "summary": {
                "assets": len(self.assets),
                "findings": len(self.findings),
                "by_severity": self.counts_by_severity(),
            },
            "assets": [asdict(a) for a in self.assets],
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
