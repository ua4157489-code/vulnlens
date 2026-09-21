"""Collector interface and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Type

from defusedxml import ElementTree as SafeET  # blocks XXE / entity-expansion attacks

from vulnlens.core.models import ScanResult


class ParseError(Exception):
    """Raised when a scan file cannot be parsed."""


class Collector(ABC):
    """Base class for scan-file parsers. Subclass and register to add a new source."""

    name: str = ""

    @abstractmethod
    def matches(self, root_tag: str) -> bool:
        """Return True if this collector can parse a document with this XML root tag."""

    @abstractmethod
    def parse(self, path: Path) -> ScanResult:
        """Parse the file at ``path`` into a normalized ScanResult."""


def load_xml(path: Path):
    """Parse an XML file safely and return its root element."""
    try:
        return SafeET.parse(str(path)).getroot()
    except SafeET.ParseError as exc:
        raise ParseError(f"{path}: invalid XML ({exc})") from exc
    except OSError as exc:
        raise ParseError(f"{path}: cannot read file ({exc})") from exc
    except Exception as exc:  # defusedxml raises its own errors for forbidden constructs
        raise ParseError(f"{path}: rejected unsafe or malformed XML ({exc})") from exc


def _registry() -> Dict[str, Type[Collector]]:
    from vulnlens.collectors.nmap import NmapCollector
    from vulnlens.collectors.openvas import OpenVASCollector

    return {c.name: c for c in (NmapCollector, OpenVASCollector)}


def get_collector(name: str) -> Collector:
    try:
        return _registry()[name]()
    except KeyError:
        raise ParseError(f"unknown format '{name}' (choose from: {', '.join(_registry())})")


def detect_collector(path: Path) -> Collector:
    """Pick a collector by inspecting the XML root element."""
    root = load_xml(path)
    for cls in _registry().values():
        collector = cls()
        if collector.matches(root.tag):
            return collector
    raise ParseError(f"{path}: unrecognized scan format (root <{root.tag}>)")
