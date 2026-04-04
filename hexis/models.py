"""Core data models for HEXIS MCP Guard."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    rule_id: str = Field(description="e.g. HEXIS-SSRF-001")
    title: str
    description: str
    severity: Severity
    score: float = Field(ge=0.0, le=10.0, description="CVSS-style score")
    cwe: str | None = Field(default=None, description="e.g. CWE-78")
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    fix_suggestion: str | None = None
    category: str = Field(
        description=(
            "ssrf, shell_injection, auth, prompt_injection, "
            "resource_exposure, transport"
        )
    )


class ScanConfig(BaseModel):
    target: str
    mode: str = "static"  # static, dynamic, full
    output_format: str = "text"  # text, json, sarif
    fail_on: Severity | None = None
    enable_ai: bool = False
    include_fixes: bool = False
    baseline_path: str | None = None


class ScanReport(BaseModel):
    tool_name: str = "hexis-mcp-guard"
    tool_version: str
    mcp_spec_version: str = "2025-03-26"
    scan_target: str
    scan_mode: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    duration_seconds: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if any(f.severity == Severity.CRITICAL for f in self.findings):
            return 2
        if any(f.severity == Severity.HIGH for f in self.findings):
            return 1
        return 0

    def build_summary(self) -> None:
        counts: dict[str, int] = {}
        for sev in Severity:
            counts[sev.value] = sum(1 for f in self.findings if f.severity == sev)
        counts["TOTAL"] = len(self.findings)
        self.summary = counts
