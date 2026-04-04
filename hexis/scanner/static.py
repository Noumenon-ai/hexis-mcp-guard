"""Static analysis scanner that parses source code for vulnerability patterns."""

from __future__ import annotations

import ast
import json
import logging
import time
from pathlib import Path
from typing import Any

from hexis import __version__
from hexis.checks import get_registry
from hexis.models import Finding, ScanReport

logger = logging.getLogger(__name__)

SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
IGNORED_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}
MCP_CONFIG_NAMES = {
    "server.json",
    "claude_desktop_config.json",
    "mcp.json",
    "mcp_config.json",
    "config.json",
}


def scan_directory(target: str, include_fixes: bool = False) -> ScanReport:
    """Scan a directory of MCP server source code for vulnerabilities."""
    start = time.time()
    target_path = Path(target).resolve()
    findings: list[Finding] = []
    registry = get_registry()

    if target_path.is_file():
        files = [target_path]
    elif target_path.is_dir():
        files = []
        for file_path in target_path.rglob("*"):
            if any(part in IGNORED_DIR_NAMES for part in file_path.parts):
                continue
            if not file_path.is_file() or file_path.is_symlink():
                continue
            if file_path.suffix not in SCANNABLE_EXTENSIONS:
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            files.append(file_path)
    else:
        return _empty_report(target, start)

    for file_path in sorted(files):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        tree: ast.AST | None = None
        if file_path.suffix == ".py":
            try:
                tree = ast.parse(content)
            except SyntaxError:
                pass

        config: dict[str, Any] | None = None
        if file_path.name in MCP_CONFIG_NAMES or file_path.suffix == ".json":
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    config = parsed
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        for check in registry.checks:
            if config is not None:
                try:
                    findings.extend(check.check_config(config))
                except Exception:
                    logger.debug(
                        "Config check %s failed on %s",
                        check.rule_id,
                        file_path,
                        exc_info=True,
                    )

            try:
                findings.extend(check.check_source(file_path, content, tree))
            except Exception:
                logger.debug("Check %s failed on %s", check.rule_id, file_path, exc_info=True)

    findings = _deduplicate_findings(findings)
    if not include_fixes:
        for finding in findings:
            finding.fix_suggestion = None

    report = ScanReport(
        tool_version=__version__,
        scan_target=str(target_path),
        scan_mode="static",
        duration_seconds=round(time.time() - start, 3),
        findings=findings,
    )
    report.build_summary()
    return report


def _empty_report(target: str, start: float) -> ScanReport:
    report = ScanReport(
        tool_version=__version__,
        scan_target=target,
        scan_mode="static",
        duration_seconds=round(time.time() - start, 3),
    )
    report.build_summary()
    return report


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, int | None, str | None]] = set()
    # Track (rule_id, file_path) pairs that have a source-level finding (with line number)
    # so we can drop config-level duplicates (line_number=None) of the same rule+file.
    source_keys: set[tuple[str, str | None]] = set()
    deduplicated: list[Finding] = []

    # First pass: collect all (rule_id, file_path) pairs with line numbers
    for finding in findings:
        if finding.line_number is not None:
            source_keys.add((finding.rule_id, finding.file_path))

    for finding in findings:
        # Skip config-level finding if a source-level finding exists for same rule+file
        if finding.line_number is None and (finding.rule_id, finding.file_path) in source_keys:
            continue
        key = (
            finding.rule_id,
            finding.file_path,
            finding.line_number,
            finding.code_snippet,
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


class StaticScanner:
    """Compatibility wrapper for earlier scanner API consumers."""

    def scan(self, target: str, include_fixes: bool = False) -> ScanReport:
        return scan_directory(target, include_fixes=include_fixes)
