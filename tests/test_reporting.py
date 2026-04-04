from __future__ import annotations

import io
import json

from rich.console import Console

from hexis.models import Finding, ScanReport, Severity
from hexis.reporting.json_report import to_json
from hexis.reporting.sarif import to_sarif
from hexis.reporting.text_report import print_report


def _sample_report() -> ScanReport:
    report = ScanReport(
        tool_version="0.1.0",
        scan_target="/test/path",
        scan_mode="static",
        duration_seconds=1.25,
        findings=[
            Finding(
                rule_id="HEXIS-SSRF-001",
                title="Test SSRF finding",
                description="URL parameter is not validated.",
                severity=Severity.HIGH,
                score=7.5,
                cwe="CWE-918",
                file_path="/test/file.py",
                line_number=10,
                code_snippet='url = args["url"]',
                fix_suggestion="Restrict outbound domains.",
                category="ssrf",
            ),
            Finding(
                rule_id="HEXIS-CMD-003",
                title="Eval used on expression",
                description="eval() is used on tool input.",
                severity=Severity.CRITICAL,
                score=10.0,
                cwe="CWE-95",
                file_path="/test/calc.py",
                line_number=5,
                code_snippet="return eval(expression)",
                fix_suggestion="Replace eval() with safe parsing.",
                category="shell_injection",
            ),
            Finding(
                rule_id="HEXIS-CMD-003",
                title="Eval used on expression",
                description="eval() is used on another tool input.",
                severity=Severity.CRITICAL,
                score=10.0,
                cwe="CWE-95",
                file_path="/test/other.py",
                line_number=18,
                code_snippet="result = eval(command)",
                fix_suggestion="Replace eval() with safe parsing.",
                category="shell_injection",
            ),
        ],
    )
    report.build_summary()
    return report


def test_json_report_round_trips() -> None:
    report = _sample_report()
    parsed = json.loads(to_json(report))

    assert parsed["tool_name"] == "hexis-mcp-guard"
    assert parsed["summary"]["TOTAL"] == 3
    assert len(parsed["findings"]) == 3


def test_json_report_preserves_severity_strings() -> None:
    report = _sample_report()
    parsed = json.loads(to_json(report))

    severities = {finding["severity"] for finding in parsed["findings"]}
    assert severities == {"HIGH", "CRITICAL"}


def test_sarif_has_valid_top_level_structure() -> None:
    report = _sample_report()
    sarif = json.loads(to_sarif(report))

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "hexis-mcp-guard"


def test_sarif_deduplicates_rules_by_rule_id() -> None:
    report = _sample_report()
    sarif = json.loads(to_sarif(report))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 2
    assert {rule["id"] for rule in rules} == {"HEXIS-SSRF-001", "HEXIS-CMD-003"}


def test_sarif_includes_locations_and_fixes() -> None:
    report = _sample_report()
    sarif = json.loads(to_sarif(report))
    result = sarif["runs"][0]["results"][0]

    assert "locations" in result
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert result["fixes"][0]["description"]["text"] == "Restrict outbound domains."


def test_text_report_renders_findings_and_summary() -> None:
    report = _sample_report()
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, color_system=None, width=120)

    print_report(report, console)
    output = buffer.getvalue()

    assert "HEXIS MCP Guard v0.1.0" in output
    assert "HEXIS-SSRF-001" in output
    assert "Summary" in output
    assert "CRITICAL findings detected" in output


def test_text_report_handles_empty_report() -> None:
    report = ScanReport(tool_version="0.1.0", scan_target="/empty", scan_mode="static")
    report.build_summary()
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, color_system=None, width=120)

    print_report(report, console)
    output = buffer.getvalue()

    assert "No vulnerabilities found." in output
