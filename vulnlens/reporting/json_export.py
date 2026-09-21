"""JSON export."""

from __future__ import annotations

import json

from vulnlens.core.models import ScanResult


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)
