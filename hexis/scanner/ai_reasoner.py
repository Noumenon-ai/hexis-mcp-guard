"""Optional AI-powered analysis of MCP tool definitions using Claude."""

from __future__ import annotations

import json
import os
from typing import Any

from hexis.models import Finding, Severity

AI_AVAILABLE = False
try:
    import anthropic

    AI_AVAILABLE = True
except ImportError:
    pass

SYSTEM_PROMPT = (
    "You are a security analyst reviewing MCP (Model Context Protocol) tool definitions "
    "for vulnerabilities.\n\n"
    "For each issue found, respond with a JSON array of objects:\n"
    '{\n'
    '  "rule_id": "HEXIS-AI-NNN",\n'
    '  "title": "Short title",\n'
    '  "description": "What the vulnerability is and how it could be exploited",\n'
    '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
    '  "score": 0.0-10.0,\n'
    '  "category": "ssrf|shell_injection|auth|prompt_injection|resource_exposure|transport",\n'
    '  "fix_suggestion": "How to fix it"\n'
    "}\n\n"
    "Only report real, actionable security issues. No false positives. "
    "Respond with JSON array only."
)


def analyze_tools(tools: list[dict[str, Any]]) -> list[Finding]:
    """Use Claude to analyze tool definitions for security issues."""
    if not AI_AVAILABLE or not os.getenv("ANTHROPIC_API_KEY") or not tools:
        return []

    try:
        client = anthropic.Anthropic()
        max_tools_size = 100_000
        tools_json = json.dumps(tools, indent=2, ensure_ascii=True)
        if len(tools_json) > max_tools_size:
            # Truncate by removing tools from the end to keep valid JSON
            truncated = list(tools)
            while len(truncated) > 1:
                truncated.pop()
                tools_json = json.dumps(truncated, indent=2, ensure_ascii=True)
                if len(tools_json) <= max_tools_size:
                    break
        response = client.messages.create(
            model=os.getenv("HEXIS_AI_MODEL", "claude-sonnet-4-6"),
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Analyze these tool definitions and identify security risks:",
                        },
                        {
                            "type": "text",
                            "text": tools_json,
                            "cache_control": {"type": "ephemeral"},
                        },
                    ],
                }
            ],
        )

        text = "".join(getattr(block, "text", "") for block in response.content)
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        issues = json.loads(text.strip())
        if not isinstance(issues, list):
            return []

        findings: list[Finding] = []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            try:
                findings.append(
                    Finding(
                        rule_id=issue.get("rule_id", "HEXIS-AI-001"),
                        title=issue["title"],
                        description=issue["description"],
                        severity=Severity(issue.get("severity", "MEDIUM")),
                        score=float(issue.get("score", 5.0)),
                        category=issue.get("category", "prompt_injection"),
                        fix_suggestion=issue.get("fix_suggestion"),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return findings
    except Exception:
        return []
