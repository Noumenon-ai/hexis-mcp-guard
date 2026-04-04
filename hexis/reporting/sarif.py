"""SARIF 2.1.0 output for GitHub Security tab integration."""

from __future__ import annotations

import json
import shlex
from typing import Any

from hexis.models import ScanReport, Severity

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

SEVERITY_TO_SECURITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "note",
}


def to_sarif(report: ScanReport) -> str:
    """Convert scan report to SARIF 2.1.0 JSON string."""
    rules: list[dict[str, Any]] = []
    rule_ids_seen: set[str] = set()
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        if finding.rule_id not in rule_ids_seen:
            rule_ids_seen.add(finding.rule_id)
            rule: dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF[finding.severity],
                },
                "properties": {
                    "security-severity": str(finding.score),
                    "tags": ["security", finding.category],
                },
            }
            if finding.cwe:
                rule["properties"]["tags"].append(finding.cwe)
            if finding.fix_suggestion:
                rule["help"] = {
                    "text": finding.fix_suggestion,
                    "markdown": f"**Fix:** {finding.fix_suggestion}",
                }
            rules.append(rule)

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": next(
                idx for idx, rule in enumerate(rules) if rule["id"] == finding.rule_id
            ),
            "level": SEVERITY_TO_SARIF[finding.severity],
            "message": {"text": finding.description},
            "properties": {
                "security-severity": str(finding.score),
            },
        }

        if finding.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            }
            if finding.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line_number,
                }
            if finding.code_snippet:
                region = location["physicalLocation"].setdefault("region", {})
                region["snippet"] = {"text": finding.code_snippet}
            result["locations"] = [location]

        if finding.fix_suggestion:
            result["fixes"] = [
                {
                    "description": {"text": finding.fix_suggestion},
                }
            ]

        results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool_name,
                        "version": report.tool_version,
                        "informationUri": (
                            "https://github.com/hexis-security/hexis-mcp-guard"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"hexis scan {shlex.quote(report.scan_target)}",
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
