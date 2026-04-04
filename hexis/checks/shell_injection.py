"""Shell/command injection detection checks."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from hexis.checks import registry
from hexis.checks.base import BaseCheck
from hexis.models import Finding, Severity
from hexis.spec.mcp_patterns import EVAL_FUNCTIONS, SHELL_DANGEROUS_CALLS


class SubprocessUserInput(BaseCheck):
    rule_id = "HEXIS-CMD-001"
    title = "subprocess/exec with user input"
    description = (
        "Subprocess or OS exec call uses variables that may contain user input. "
        "This enables arbitrary command execution."
    )
    severity = Severity.CRITICAL
    score = 9.8
    cwe = "CWE-78"
    category = "shell_injection"
    fix_suggestion = (
        "Use subprocess with a list of arguments (not shell=True). "
        "Never pass user input to shell commands."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for call in SHELL_DANGEROUS_CALLS:
                if call in stripped:
                    # Flag if using variables (not just static strings)
                    if re.search(r'\(.*[a-zA-Z_]\w*', stripped):
                        findings.append(
                            self._make_finding(
                                file_path=str(file_path),
                                line_number=i,
                                code_snippet=stripped,
                            )
                        )
                        break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


class ShellTrueInterpolation(BaseCheck):
    rule_id = "HEXIS-CMD-002"
    title = "shell=True with string interpolation"
    description = (
        "Using shell=True with f-strings or .format() allows shell metacharacter injection."
    )
    severity = Severity.CRITICAL
    score = 9.5
    cwe = "CWE-78"
    category = "shell_injection"
    fix_suggestion = (
        "Remove shell=True and pass command as a list. "
        "Use shlex.quote() if shell is required."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if "shell=True" in stripped or "shell = True" in stripped:
                if re.search(r'f["\']|\.format\(|%\s', stripped):
                    findings.append(
                        self._make_finding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=stripped,
                        )
                    )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


class EvalExecOnInput(BaseCheck):
    rule_id = "HEXIS-CMD-003"
    title = "eval/exec on tool arguments"
    description = (
        "Using eval() or exec() on data derived from tool arguments "
        "enables arbitrary code execution."
    )
    severity = Severity.CRITICAL
    score = 10.0
    cwe = "CWE-95"
    category = "shell_injection"
    fix_suggestion = (
        "Never use eval/exec on user input. "
        "Use ast.literal_eval() for safe parsing, or a proper parser."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for func in EVAL_FUNCTIONS:
                if re.search(rf'(?<!\.)(?<!\w)\b{func}\s*\(', stripped):
                    findings.append(
                        self._make_finding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=stripped,
                        )
                    )
                    break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []


registry.register(SubprocessUserInput())
registry.register(ShellTrueInterpolation())
registry.register(EvalExecOnInput())
