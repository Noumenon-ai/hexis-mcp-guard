"""SSRF detection checks for MCP servers."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from hexis.checks import registry
from hexis.checks.base import BaseCheck
from hexis.models import Finding, Severity
from hexis.spec.mcp_patterns import (
    INTERNAL_IP_PATTERNS,
    SSRF_FETCH_FUNCTIONS,
    SSRF_URL_PARAMS,
)


class SSRFUrlParam(BaseCheck):
    rule_id = "HEXIS-SSRF-001"
    title = "URL parameter in tool inputSchema without validation"
    description = (
        "Tool accepts a URL parameter in its input schema without apparent validation. "
        "An attacker could supply arbitrary URLs to perform SSRF attacks."
    )
    severity = Severity.HIGH
    score = 7.5
    cwe = "CWE-918"
    category = "ssrf"
    fix_suggestion = "Add URL allowlist validation or restrict to specific domains/protocols."

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            lower = line.lower()
            for param in SSRF_URL_PARAMS:
                if re.search(rf'["\']({param})["\']\s*:', lower):
                    if not re.search(r"validat|allowlist|whitelist|check_url|sanitiz", lower):
                        findings.append(
                            self._make_finding(
                                file_path=str(file_path),
                                line_number=i,
                                code_snippet=line.strip(),
                            )
                        )
                        break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        tools = config.get("tools", [])
        for tool in tools:
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            for prop_name, prop_def in props.items():
                if prop_name.lower() in SSRF_URL_PARAMS or prop_def.get("format") == "uri":
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Tool '{tool.get('name', '?')}' accepts URL param "
                                f"'{prop_name}' without validation."
                            ),
                        )
                    )
        return findings


class SSRFServerFetch(BaseCheck):
    rule_id = "HEXIS-SSRF-002"
    title = "Server-side fetch with user-controlled URL"
    description = (
        "Server performs HTTP requests using URLs derived from user/tool input. "
        "This enables SSRF to internal services."
    )
    severity = Severity.CRITICAL
    score = 9.0
    cwe = "CWE-918"
    category = "ssrf"
    fix_suggestion = "Validate URLs against an allowlist before fetching. Block private IP ranges."

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for func in SSRF_FETCH_FUNCTIONS:
                if func in line:
                    # Check if the URL argument uses a variable (not a hardcoded string)
                    if re.search(r'\(.*[a-zA-Z_]\w*.*\)', line) and not re.search(
                        r"""\(['"](https?://[^'"]+)['"]\)""", line
                    ):
                        findings.append(
                            self._make_finding(
                                file_path=str(file_path),
                                line_number=i,
                                code_snippet=line.strip(),
                            )
                        )
                        break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


class SSRFInternalAccess(BaseCheck):
    rule_id = "HEXIS-SSRF-003"
    title = "Internal IP/metadata endpoint accessible"
    description = (
        "Code references internal IPs or cloud metadata endpoints, "
        "which could be exploited via SSRF to access sensitive infrastructure."
    )
    severity = Severity.CRITICAL
    score = 9.5
    cwe = "CWE-918"
    category = "ssrf"
    fix_suggestion = "Block requests to private IP ranges and cloud metadata endpoints."

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in INTERNAL_IP_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        self._make_finding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            description=(
                                "Reference to internal/metadata IP found: "
                                f"{line.strip()[:80]}"
                            ),
                        )
                    )
                    break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


# Register all checks
registry.register(SSRFUrlParam())
registry.register(SSRFServerFetch())
registry.register(SSRFInternalAccess())
