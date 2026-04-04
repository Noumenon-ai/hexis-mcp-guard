"""Prompt injection detection checks for MCP servers."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from hexis.checks import registry
from hexis.checks.base import BaseCheck
from hexis.models import Finding, Severity
from hexis.spec.mcp_patterns import PROMPT_INJECTION_PATTERNS


class PromptInjectionInDescription(BaseCheck):
    rule_id = "HEXIS-PI-001"
    title = "Tool description contains injection patterns"
    description = (
        "Tool description contains text patterns commonly used in prompt injection attacks. "
        "A poisoned tool description can manipulate LLM behavior when the model reads tool metadata."
    )
    severity = Severity.HIGH
    score = 8.5
    cwe = "CWE-94"
    category = "prompt_injection"
    fix_suggestion = (
        "Remove injection-like language from tool descriptions. "
        "Descriptions should be neutral and factual."
    )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self._make_finding(
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip()[:120],
                        )
                    )
                    break
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for tool in config.get("tools", []):
            desc = tool.get("description", "")
            for pattern in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, desc, re.IGNORECASE):
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Tool '{tool.get('name', '?')}' description contains "
                                "prompt injection patterns."
                            ),
                        )
                    )
                    break
        return findings


class UnsanitizedToolOutput(BaseCheck):
    rule_id = "HEXIS-PI-002"
    title = "Return values flow unsanitized to LLM context"
    description = (
        "Tool handler returns external data directly to the LLM without sanitization. "
        "Malicious content in the response could inject instructions into the LLM context."
    )
    severity = Severity.MEDIUM
    score = 6.5
    cwe = "CWE-94"
    category = "prompt_injection"
    fix_suggestion = (
        "Sanitize or escape tool outputs before returning them to the LLM. "
        "Strip control characters and instruction-like patterns."
    )

    SUSPICIOUS_RETURN_NAMES = re.compile(
        r"(?:tool_?output|response|payload|body|text|stdout|stderr)\Z",
        re.IGNORECASE,
    )
    SUSPICIOUS_RETURN_ATTRS = {"body", "content", "output", "stdout", "stderr", "text"}
    TOOL_FUNCTION_NAMES = re.compile(r"(?:^tool_|^handle_|^call_tool$|tool_handler)", re.IGNORECASE)
    SANITIZER_HINTS = ("clean", "escape", "filter", "sanitize", "strip")

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        if tree is not None:
            findings.extend(self._check_python_ast(file_path, content, tree))
            return findings

        if re.search(r"@.*tool|def\s+handle_|def\s+call_tool|tool_handler", content):
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if re.search(r"return\s+.*\.(text|content|body|read|output|stdout)", stripped):
                    if not re.search(r"sanitiz|escape|strip|clean|filter", stripped, re.IGNORECASE):
                        findings.append(
                            self._make_finding(
                                file_path=str(file_path),
                                line_number=i,
                                code_snippet=stripped[:120],
                            )
                        )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        return []

    def _check_python_ast(
        self,
        file_path: Path,
        content: str,
        tree: ast.AST,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._is_tool_handler(node):
                continue
            for return_node in ast.walk(node):
                if not isinstance(return_node, ast.Return) or return_node.value is None:
                    continue
                if self._is_sanitized_return(return_node.value):
                    continue
                if not self._is_suspicious_return(return_node.value):
                    continue
                snippet = ast.get_source_segment(content, return_node) or "return ..."
                findings.append(
                    self._make_finding(
                        file_path=str(file_path),
                        line_number=return_node.lineno,
                        code_snippet=snippet.strip()[:120],
                    )
                )
        return findings

    def _is_tool_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if self.TOOL_FUNCTION_NAMES.search(node.name):
            return True
        for decorator in node.decorator_list:
            name = self._call_name(decorator)
            if name is not None and "tool" in name.lower():
                return True
        return False

    def _is_suspicious_return(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return bool(self.SUSPICIOUS_RETURN_NAMES.search(node.id))
        if isinstance(node, ast.Attribute):
            return node.attr in self.SUSPICIOUS_RETURN_ATTRS
        return False

    def _is_sanitized_return(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        name = self._call_name(node.func)
        return name is not None and any(hint in name.lower() for hint in self.SANITIZER_HINTS)

    def _call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


class HiddenUnicodeInToolDef(BaseCheck):
    rule_id = "HEXIS-PI-003"
    title = "Tool poisoning via hidden instructions in descriptions"
    description = (
        "Tool definitions contain zero-width or invisible Unicode characters that could be used "
        "to hide malicious instructions from human reviewers."
    )
    severity = Severity.HIGH
    score = 8.0
    cwe = "CWE-94"
    category = "prompt_injection"
    fix_suggestion = (
        "Remove all zero-width and invisible Unicode characters from tool definitions."
    )

    HIDDEN_UNICODE = re.compile(
        r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
        r"\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e]"
    )
    HIDDEN_UNICODE_ESCAPES = re.compile(
        r"\\u(?:200[b-f]|206[0-4]|feff|00ad|034f|061c|115f|1160|17b[45]|180e)",
        re.IGNORECASE,
    )

    def _contains_hidden_unicode(self, text: str) -> bool:
        return bool(
            self.HIDDEN_UNICODE.search(text) or self.HIDDEN_UNICODE_ESCAPES.search(text)
        )

    def check_source(self, file_path: Path, content: str, tree: ast.AST | None) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if self._contains_hidden_unicode(line):
                findings.append(
                    self._make_finding(
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=repr(line.strip())[:120],
                    )
                )
        return findings

    def check_config(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for tool in config.get("tools", []):
            text = str(tool.get("description", "")) + str(tool.get("name", ""))
            if self._contains_hidden_unicode(text):
                findings.append(
                    self._make_finding(
                        description=(
                            f"Tool '{tool.get('name', '?')}' contains hidden Unicode characters."
                        ),
                    )
                )
        return findings


registry.register(PromptInjectionInDescription())
registry.register(UnsanitizedToolOutput())
registry.register(HiddenUnicodeInToolDef())
