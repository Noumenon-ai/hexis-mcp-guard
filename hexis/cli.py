"""HEXIS MCP Guard CLI - Typer-based command interface."""

from __future__ import annotations

import asyncio
import json
from io import StringIO
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from hexis import __version__
from hexis.checks import get_registry
from hexis.models import Finding, ScanReport, Severity
from hexis.reporting.json_report import to_json
from hexis.reporting.sarif import to_sarif
from hexis.reporting.text_report import print_report
from hexis.scanner.static import IGNORED_DIR_NAMES, MAX_FILE_SIZE, scan_directory

app = typer.Typer(
    name="hexis",
    help="HEXIS MCP Guard - Security scanner for MCP servers",
    no_args_is_help=True,
)
console = Console()

VALID_FORMATS = {"text", "json", "sarif"}
SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
BASELINE_KEYS = {"category", "file_path", "line_number", "rule_id", "title"}


@app.command()
def scan(
    path: str | None = typer.Argument(
        None,
        help="Path to MCP server source directory",
    ),
    url: str | None = typer.Option(
        None,
        "--url",
        help="URL of running MCP server",
    ),
    dynamic: bool = typer.Option(
        False,
        "--dynamic",
        help="Enable dynamic probing",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, json, sarif",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode - minimal output, exit codes",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Fail on severity: critical, high, medium, low, info",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable AI-powered analysis (requires ANTHROPIC_API_KEY)",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Include fix suggestions in output",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        dir_okay=False,
        help="Path to baseline file for suppressing known findings",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write report to file",
    ),
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    output_format = format.lower()
    if output_format not in VALID_FORMATS:
        raise typer.BadParameter(
            "Format must be one of: text, json, sarif.",
            param_hint="--format",
        )

    if not path and not url:
        console.print("[red]Error:[/] Provide a path or --url to scan.")
        raise typer.Exit(1)

    if url and not dynamic and not path:
        console.print("[red]Error:[/] Use --dynamic with --url, or provide a path.")
        raise typer.Exit(1)

    if path and url and dynamic:
        report = _merge_reports(
            scan_directory(path, include_fixes=fix),
            asyncio.run(_probe(url, include_fixes=fix)),
        )
    elif dynamic and url:
        report = asyncio.run(_probe(url, include_fixes=fix))
    elif path:
        report = scan_directory(path, include_fixes=fix)
        if ai:
            from hexis.scanner.ai_reasoner import analyze_tools

            ai_findings = analyze_tools(_extract_tools(path))
            if ai_findings:
                report.findings.extend(ai_findings)
                report.build_summary()
    else:
        console.print("[red]Error:[/] Use --url with --dynamic, or provide a path.")
        raise typer.Exit(1)

    if baseline is not None:
        if baseline.exists():
            _apply_baseline(report, baseline)
        else:
            console.print(f"[yellow]Warning:[/] Baseline file not found: {baseline}")

    exit_code = report.exit_code
    if fail_on:
        exit_code = 1 if _has_findings_at_or_above(report, _parse_severity(fail_on)) else 0

    _emit_report(report, output_format, output)

    if ci and exit_code:
        console.print(f"[red]Scan failed with exit code {exit_code}[/]")

    raise typer.Exit(exit_code)


@app.command()
def version() -> None:
    """Show HEXIS MCP Guard version."""
    typer.echo(f"hexis-mcp-guard v{__version__}")


@app.command()
def rules() -> None:
    """List all security rules with descriptions."""
    registry = get_registry()
    table = Table(title="HEXIS MCP Guard Rules", show_header=True, header_style="bold cyan")
    table.add_column("Rule ID", style="bold")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Title")
    table.add_column("Description")
    table.add_column("CWE", style="dim")

    severity_colors = {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold blue",
        Severity.INFO: "dim",
    }

    for check in sorted(registry.checks, key=lambda item: item.rule_id):
        severity_text = Text(check.severity.value, style=severity_colors.get(check.severity, ""))
        table.add_row(
            check.rule_id,
            severity_text,
            f"{check.score:.1f}",
            check.title,
            check.description,
            check.cwe or "",
        )

    console.print(table)
    typer.echo(f"{len(registry.checks)} rules loaded")


async def _probe(url: str, include_fixes: bool) -> ScanReport:
    from hexis.scanner.dynamic import probe_server

    return await probe_server(url, include_fixes=include_fixes)


def _merge_reports(static_report: ScanReport, dynamic_report: ScanReport) -> ScanReport:
    report = ScanReport(
        tool_version=__version__,
        scan_target=f"{static_report.scan_target} + {dynamic_report.scan_target}",
        scan_mode="full",
        duration_seconds=round(
            static_report.duration_seconds + dynamic_report.duration_seconds,
            3,
        ),
        findings=[*static_report.findings, *dynamic_report.findings],
    )
    report.build_summary()
    return report


def _emit_report(report: ScanReport, output_format: str, output: Path | None) -> None:
    rendered: str | None
    if output_format == "json":
        rendered = to_json(report)
    elif output_format == "sarif":
        rendered = to_sarif(report)
    else:
        rendered = None

    if rendered is not None:
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"[green]Report written to {output}[/]")
        else:
            typer.echo(rendered)
        return

    if output is not None:
        buffer = StringIO()
        file_console = Console(file=buffer, force_terminal=False, color_system=None)
        print_report(report, console=file_console)
        output.write_text(buffer.getvalue(), encoding="utf-8")
        console.print(f"[green]Report written to {output}[/]")
        return

    print_report(report, console)


def _parse_severity(value: str) -> Severity:
    normalized = value.strip().upper()
    try:
        return Severity(normalized)
    except ValueError as exc:
        valid = ", ".join(severity.value.lower() for severity in Severity)
        raise typer.BadParameter(
            f"Severity must be one of: {valid}.",
            param_hint="--fail-on",
        ) from exc


def _has_findings_at_or_above(report: ScanReport, threshold: Severity) -> bool:
    threshold_rank = SEVERITY_ORDER[threshold]
    return any(
        SEVERITY_ORDER[finding.severity] >= threshold_rank
        for finding in report.findings
    )


def _apply_baseline(report: ScanReport, baseline_path: Path) -> None:
    entries = _load_baseline_entries(baseline_path)
    report.findings = [
        finding
        for finding in report.findings
        if not any(_matches_baseline_entry(finding, entry) for entry in entries)
    ]
    report.build_summary()


def _load_baseline_entries(baseline_path: Path) -> list[dict[str, Any]]:
    try:
        loaded = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            f"Baseline file is not valid JSON: {baseline_path}",
            param_hint="--baseline",
        ) from exc

    if isinstance(loaded, dict):
        raw_entries = loaded.get("findings", loaded.get("ignored", []))
    else:
        raw_entries = loaded

    if not isinstance(raw_entries, list) or not all(
        isinstance(entry, dict) for entry in raw_entries
    ):
        raise typer.BadParameter(
            (
                "Baseline JSON must be a list of finding match objects "
                "or an object with a findings list."
            ),
            param_hint="--baseline",
        )

    return [dict(entry) for entry in raw_entries]


def _matches_baseline_entry(finding: Finding, entry: dict[str, Any]) -> bool:
    supported_keys = BASELINE_KEYS.intersection(entry)
    if not supported_keys:
        return False

    finding_data = finding.model_dump()
    return all(finding_data.get(key) == entry.get(key) for key in supported_keys)


def _extract_tools(target: str) -> list[dict[str, Any]]:
    target_path = Path(target)
    if not target_path.exists():
        return []

    if target_path.is_file():
        files = [target_path]
    else:
        files = [
            f
            for f in sorted(target_path.rglob("*.json"))
            if not f.is_symlink()
            and not any(part in IGNORED_DIR_NAMES for part in f.parts)
        ]
    tools: list[dict[str, Any]] = []
    for file_path in files:
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE:
                continue
            loaded = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        if isinstance(loaded, dict):
            raw_tools = loaded.get("tools", [])
            if isinstance(raw_tools, list):
                tools.extend(tool for tool in raw_tools if isinstance(tool, dict))
    return tools
