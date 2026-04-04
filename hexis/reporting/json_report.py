"""JSON report output."""

from __future__ import annotations

import json

from hexis.models import ScanReport


def to_json(report: ScanReport) -> str:
    """Convert scan report to JSON string."""
    return json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2)
