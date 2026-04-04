"""Transport security checks."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hexis.checks import registry
from hexis.checks.base import BaseCheck
from hexis.models import Finding, Severity


class PlaintextTransport(BaseCheck):
    rule_id = "HEXIS-TLS-001"
    title = "Plaintext HTTP transport in production"
    description = (
        "MCP server uses unencrypted HTTP transport. "
        "All communication including tool arguments and responses are transmitted in cleartext."
    )
    severity = Severity.MEDIUM
    score = 5.5
    cwe = "CWE-319"
    category = "transport"
    fix_suggestion = "Use HTTPS/TLS for all non-localhost transports. Configure TLS certificates."

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Match http:// URLs that are NOT localhost/127.0.0.1
            matches = re.findall(r'http://([^\s\'">/]+)', stripped)
            for host in matches:
                if not re.match(r"(localhost|127\.0\.0\.1|\[::1\])", host):
                    findings.append(
                        self._make_finding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=stripped[:120],
                            description=f"Plaintext HTTP to non-localhost host: {host[:60]}",
                        )
                    )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        url = config.get("url", config.get("endpoint", ""))
        if isinstance(url, str) and url.startswith("http://"):
            parsed = urlparse(url)
            host = (parsed.hostname or "").strip("[]")
            if host not in ("localhost", "127.0.0.1", "::1"):
                findings.append(
                    self._make_finding(
                        description=f"Config uses plaintext HTTP to {host}.",
                    )
                )
        return findings


registry.register(PlaintextTransport())
