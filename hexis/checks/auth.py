"""Authentication and authorization gap detection."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from hexis.checks import registry
from hexis.checks.base import BaseCheck
from hexis.models import Finding, Severity
from hexis.spec.mcp_patterns import AUTH_KEYWORDS


class NoAuthTransport(BaseCheck):
    rule_id = "HEXIS-AUTH-001"
    title = "No authentication on transport"
    description = (
        "MCP server transport has no authentication mechanism. "
        "Any client can connect and invoke tools."
    )
    severity = Severity.HIGH
    score = 8.0
    cwe = "CWE-306"
    category = "auth"
    fix_suggestion = (
        "Add authentication middleware (API key, OAuth, or mTLS) "
        "to the transport layer."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        has_server = bool(re.search(r"Server\(|McpServer\(|create_server|app\s*=", content))
        if not has_server:
            return findings

        has_auth = any(kw in content.lower() for kw in AUTH_KEYWORDS)
        has_transport = bool(
            re.search(r"StdioServerTransport|SSEServerTransport|StreamableHTTP|\.serve\(", content)
        )

        if has_transport and not has_auth:
            findings.append(
                self._make_finding(
                    file_path=str(file_path),
                    description="Server transport configured without any authentication mechanism.",
                )
            )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        transport = config.get("transport", {})
        auth = config.get("auth", config.get("authentication", {}))
        if transport and not auth:
            findings.append(
                self._make_finding(
                    description="Server config defines transport but no authentication.",
                )
            )
        return findings


class MissingAuthzChecks(BaseCheck):
    rule_id = "HEXIS-AUTH-002"
    title = "Missing authorization checks on sensitive tools"
    description = (
        "Tools performing sensitive operations (file I/O, shell, DB) lack "
        "authorization checks to verify the caller has permission."
    )
    severity = Severity.HIGH
    score = 7.5
    cwe = "CWE-862"
    category = "auth"
    fix_suggestion = (
        "Add role-based or scope-based authorization checks "
        "before executing sensitive operations."
    )

    SENSITIVE_OPS = [
        r"subprocess\.",
        r"os\.(system|popen|exec)",
        r"\bopen\s*\(",
        r"shutil\.",
        r"sqlite3\.",
        r"cursor\.execute",
        r"\.query\(",
    ]

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        has_sensitive = False
        has_authz = False

        for line in lines:
            for pattern in self.SENSITIVE_OPS:
                if re.search(pattern, line):
                    has_sensitive = True
                    break
            if re.search(r"check_permission|authorize|has_role|is_allowed|require_scope", line):
                has_authz = True

        if has_sensitive and not has_authz:
            # Check if this looks like an MCP tool handler
            if re.search(r"@.*tool|def\s+handle_|def\s+call_tool|tool_handler", content):
                findings.append(
                    self._make_finding(
                        file_path=str(file_path),
                        description=(
                            "Tool handler performs sensitive operations "
                            "without authorization checks."
                        ),
                    )
                )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


registry.register(NoAuthTransport())
registry.register(MissingAuthzChecks())
