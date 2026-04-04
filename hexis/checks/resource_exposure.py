"""Resource exposure detection — filesystem and SQL injection."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from hexis.checks import registry
from hexis.checks.base import BaseCheck
from hexis.models import Finding, Severity
from hexis.spec.mcp_patterns import SQL_INJECTION_PATTERNS


class UnrestrictedFileAccess(BaseCheck):
    rule_id = "HEXIS-RES-001"
    title = "Unrestricted file system access"
    description = (
        "Tool provides file system access without path validation or sandboxing. "
        "Attackers could read/write arbitrary files via path traversal."
    )
    severity = Severity.HIGH
    score = 8.0
    cwe = "CWE-22"
    category = "resource_exposure"
    fix_suggestion = (
        "Validate and resolve paths against an allowed base directory. "
        "Reject paths containing '..' or absolute paths."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        has_file_ops = False
        has_path_validation = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Detect file operations
            if re.search(r'\bopen\s*\(|Path\s*\(|os\.path|shutil\.', stripped):
                has_file_ops = True

                # Check for path traversal protection
                if re.search(
                    r'resolve\(\)|realpath|abspath|\.startswith\(|is_relative_to|'
                    r'sanitize_path|validate_path|check_path|allowed_dir',
                    content,
                ):
                    has_path_validation = True

        if has_file_ops and not has_path_validation:
            if re.search(r"@.*tool|def\s+handle_|def\s+call_tool|tool_handler", content):
                findings.append(
                    self._make_finding(
                        file_path=str(file_path),
                        description=(
                            "File operations in tool handler without path validation/"
                            "sandboxing."
                        ),
                    )
                )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for tool in config.get("tools", []):
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            for prop_name in props:
                if any(kw in prop_name.lower() for kw in ("path", "file", "dir", "folder")):
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Tool '{tool.get('name', '?')}' accepts file path "
                                f"'{prop_name}' - check for path traversal protection."
                            ),
                        )
                    )
        return findings


class SQLWithoutParameterization(BaseCheck):
    rule_id = "HEXIS-RES-002"
    title = "SQL query tool without parameterization"
    description = (
        "SQL queries built with string interpolation instead of parameterized queries. "
        "This enables SQL injection via tool arguments."
    )
    severity = Severity.HIGH
    score = 8.5
    cwe = "CWE-89"
    category = "resource_exposure"
    fix_suggestion = (
        "Use parameterized queries (cursor.execute('SELECT ?', (param,))) "
        "instead of string interpolation."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern in SQL_INJECTION_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append(
                        self._make_finding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=stripped[:120],
                        )
                    )
                    break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


registry.register(UnrestrictedFileAccess())
registry.register(SQLWithoutParameterization())
