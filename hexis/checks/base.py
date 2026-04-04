"""Abstract base class for all security checks."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from hexis.models import Finding, Severity


class BaseCheck(ABC):
    """Base class all checks must inherit from."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    score: float
    cwe: str | None = None
    category: str
    fix_suggestion: str | None = None

    @abstractmethod
    def check_source(
        self,
        file_path: Path,
        content: str,
        tree: ast.AST | None,
    ) -> list[Finding]:
        """Run check against source code. Return list of findings."""
        ...

    @abstractmethod
    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        """Run check against MCP server config/tool definitions. Return list of findings."""
        ...

    def _make_finding(
        self,
        *,
        file_path: str | None = None,
        line_number: int | None = None,
        code_snippet: str | None = None,
        description: str | None = None,
        fix: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=description or self.description,
            severity=self.severity,
            score=self.score,
            cwe=self.cwe,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            fix_suggestion=fix or self.fix_suggestion,
            category=self.category,
        )
