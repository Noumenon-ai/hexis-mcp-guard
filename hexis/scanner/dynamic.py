"""Dynamic scanner - probes a live MCP server with crafted payloads."""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from hexis import __version__
from hexis.models import Finding, ScanReport, Severity
from hexis.spec.mcp_patterns import PROMPT_INJECTION_PATTERNS

SSRF_PROBES = [
    {"name": "metadata_aws", "url": "http://169.254.169.254/latest/meta-data/"},
    {
        "name": "metadata_gcp",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
    },
    {"name": "localhost_probe", "url": "http://127.0.0.1:22"},
]

INJECTION_PROBES = [
    {"name": "shell_semicolon", "payload": "; cat /etc/passwd"},
    {"name": "shell_pipe", "payload": "| id"},
    {"name": "shell_backtick", "payload": "`whoami`"},
    {"name": "path_traversal", "payload": "../../../../etc/passwd"},
]

HIDDEN_UNICODE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e]"
)
HIDDEN_UNICODE_ESCAPES = re.compile(
    r"\\u(?:200[b-f]|206[0-4]|feff|00ad|034f|061c|115f|1160|17b[45]|180e)",
    re.IGNORECASE,
)


async def probe_server(url: str, include_fixes: bool = False) -> ScanReport:
    """Probe a live MCP server for vulnerabilities via HTTP."""
    start = time.time()
    findings: list[Finding] = []

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        tools = await _get_tools(client, url)
        if tools is None:
            findings.append(
                Finding(
                    rule_id="HEXIS-DYN-001",
                    title="Server unreachable or invalid response",
                    description=f"Could not connect to MCP server at {url}",
                    severity=Severity.INFO,
                    score=0.0,
                    category="transport",
                )
            )
            return _build_report(url, findings, start, include_fixes)

        findings.append(
            Finding(
                rule_id="HEXIS-AUTH-001",
                title="No authentication on transport",
                description=(
                    "Server exposed tools/list without any authentication challenge or token "
                    "requirement."
                ),
                severity=Severity.HIGH,
                score=8.0,
                cwe="CWE-306",
                category="auth",
                fix_suggestion="Require authentication before listing or invoking tools.",
            )
        )

        findings.extend(_inspect_tool_metadata(tools))

        if url.startswith("http://"):
            from urllib.parse import urlparse as _urlparse

            host = (_urlparse(url).hostname or "").strip("[]")
            if host not in ("localhost", "127.0.0.1", "::1"):
                findings.append(
                    Finding(
                        rule_id="HEXIS-TLS-001",
                        title="Plaintext HTTP transport",
                        description=f"Server at {url} uses unencrypted HTTP",
                        severity=Severity.MEDIUM,
                        score=5.5,
                        cwe="CWE-319",
                        category="transport",
                        fix_suggestion="Use HTTPS for production deployments.",
                    )
                )

        for tool in tools:
            tool_name = str(tool.get("name", "unknown"))
            schema = _as_dict(tool.get("inputSchema")) or {}
            props = _as_dict(schema.get("properties")) or {}

            for prop_name, prop_def in props.items():
                if not isinstance(prop_name, str):
                    continue

                if any(keyword in prop_name.lower() for keyword in ("url", "uri", "endpoint", "link")):
                    for probe in SSRF_PROBES:
                        result = await _call_tool(
                            client,
                            url,
                            tool_name,
                            {prop_name: probe["url"]},
                        )
                        if result and not _is_error_response(result):
                            findings.append(
                                Finding(
                                    rule_id="HEXIS-SSRF-002",
                                    title=f"SSRF via {tool_name}.{prop_name}",
                                    description=f"Tool accepted SSRF probe ({probe['name']})",
                                    severity=Severity.CRITICAL,
                                    score=9.0,
                                    cwe="CWE-918",
                                    category="ssrf",
                                    fix_suggestion="Validate URLs against an allowlist.",
                                )
                            )

                if isinstance(prop_def, dict) and prop_def.get("type") == "string":
                    for probe in INJECTION_PROBES:
                        result = await _call_tool(
                            client,
                            url,
                            tool_name,
                            {prop_name: probe["payload"]},
                        )
                        if result and _indicates_injection(result, probe["name"]):
                            findings.append(
                                Finding(
                                    rule_id="HEXIS-CMD-001",
                                    title=f"Injection via {tool_name}.{prop_name}",
                                    description=f"Tool vulnerable to {probe['name']}",
                                    severity=Severity.CRITICAL,
                                    score=9.8,
                                    cwe="CWE-78",
                                    category="shell_injection",
                                    fix_suggestion="Sanitize all inputs. Never pass to shell.",
                                )
                            )

    findings = _deduplicate_findings(findings)
    return _build_report(url, findings, start, include_fixes)


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _as_tool_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _inspect_tool_metadata(tools: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        tool_name = str(tool.get("name", "unknown"))
        description = str(tool.get("description", ""))
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, description, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="HEXIS-PI-001",
                        title="Tool description contains injection patterns",
                        description=(
                            f"Tool '{tool_name}' description contains prompt injection language."
                        ),
                        severity=Severity.HIGH,
                        score=8.5,
                        cwe="CWE-94",
                        category="prompt_injection",
                        fix_suggestion="Remove instruction-like text from tool descriptions.",
                    )
                )
                break

        if _contains_hidden_unicode(f"{tool_name}{description}"):
            findings.append(
                Finding(
                    rule_id="HEXIS-PI-003",
                    title="Tool poisoning via hidden instructions in descriptions",
                    description=(
                        f"Tool '{tool_name}' contains hidden Unicode characters in exposed metadata."
                    ),
                    severity=Severity.HIGH,
                    score=8.0,
                    cwe="CWE-94",
                    category="prompt_injection",
                    fix_suggestion=(
                        "Remove all zero-width and invisible Unicode characters from tool "
                        "metadata."
                    ),
                )
            )
    return findings


async def _get_tools(
    client: httpx.AsyncClient,
    url: str,
) -> list[dict[str, Any]] | None:
    """Try to get the tool list from an MCP server."""
    try:
        response = await client.post(
            url,
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        if response.status_code == 200:
            data = _as_dict(response.json())
            if data is None:
                return None
            result = _as_dict(data.get("result")) or {}
            return _as_tool_list(result.get("tools"))
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return None


async def _call_tool(
    client: httpx.AsyncClient,
    url: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any] | None:
    """Call an MCP tool and return the JSON response."""
    try:
        response = await client.post(
            url,
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
                "id": 2,
            },
            timeout=5.0,
        )
        if response.status_code == 200:
            return _as_dict(response.json())
    except (httpx.HTTPError, json.JSONDecodeError):
        pass
    return None


def _is_error_response(result: dict[str, Any]) -> bool:
    """Check whether the response payload indicates an error."""
    if "error" in result:
        return True
    content = (_as_dict(result.get("result")) or {}).get("content", [])
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("isError"):
                return True
    return False


def _contains_hidden_unicode(text: str) -> bool:
    return bool(HIDDEN_UNICODE.search(text) or HIDDEN_UNICODE_ESCAPES.search(text))


def _indicates_injection(result: dict[str, Any], probe_name: str) -> bool:
    """Check if a response indicates successful command or path injection."""
    text = json.dumps(result).lower()
    indicators = {
        "shell_semicolon": ["root:", "/bin/bash", "passwd"],
        "shell_pipe": ["uid=", "gid="],
        "shell_backtick": ["uid=", "root"],
        "path_traversal": ["root:", "/bin/bash"],
    }
    return any(indicator in text for indicator in indicators.get(probe_name, []))


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    deduplicated: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.description)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


def _build_report(
    url: str,
    findings: list[Finding],
    start: float,
    include_fixes: bool,
) -> ScanReport:
    if not include_fixes:
        for finding in findings:
            finding.fix_suggestion = None
    report = ScanReport(
        tool_version=__version__,
        scan_target=url,
        scan_mode="dynamic",
        duration_seconds=round(time.time() - start, 3),
        findings=findings,
    )
    report.build_summary()
    return report
