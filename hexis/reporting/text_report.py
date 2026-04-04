"""Rich terminal output with colored severity badges and tables."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hexis.models import ScanReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
    Severity.INFO: "[i]",
}


def print_report(report: ScanReport, console: Console | None = None) -> None:
    """Print a rich formatted scan report to the terminal."""
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold cyan]HEXIS MCP Guard v{report.tool_version}[/]\n"
            f"Target: {report.scan_target}\n"
            f"Mode: {report.scan_mode} | "
            f"Duration: {report.duration_seconds:.2f}s | "
            f"MCP Spec: {report.mcp_spec_version}",
            title="[bold]Scan Report[/]",
            border_style="cyan",
        )
    )

    if not report.findings:
        console.print("\n[bold green]No vulnerabilities found.[/]\n")
        return

    # Findings
    for i, finding in enumerate(report.findings, 1):
        color = SEVERITY_COLORS[finding.severity]
        icon = SEVERITY_ICONS[finding.severity]

        # Severity badge
        badge = Text(f" {icon} {finding.severity.value} ", style=color)

        console.print()
        console.print(f"{'─' * 70}")
        console.print(
            badge,
            Text(f" {finding.rule_id} ", style="bold"),
            Text(f"(CVSS {finding.score})", style="dim"),
        )
        console.print(f"  [bold]{rich_escape(finding.title)}[/]")
        console.print(f"  {rich_escape(finding.description)}")

        if finding.file_path:
            loc = finding.file_path
            if finding.line_number:
                loc += f":{finding.line_number}"
            console.print(f"  [dim]Location:[/] {rich_escape(loc)}")

        if finding.code_snippet:
            console.print(f"  [dim]Code:[/] [italic]{rich_escape(finding.code_snippet[:120])}[/]")

        if finding.cwe:
            console.print(f"  [dim]CWE:[/] {finding.cwe}")

        if finding.fix_suggestion:
            console.print(f"  [green]Fix:[/] {rich_escape(finding.fix_suggestion)}")

    # Summary table
    console.print(f"\n{'─' * 70}")
    table = Table(title="Summary", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for sev in Severity:
        count = report.summary.get(sev.value, 0)
        if count > 0:
            table.add_row(
                Text(sev.value, style=SEVERITY_COLORS[sev]),
                str(count),
            )

    table.add_row(
        Text("TOTAL", style="bold"),
        str(report.summary.get("TOTAL", len(report.findings))),
    )

    console.print(table)

    # Exit code hint
    if report.exit_code == 2:
        console.print("\n[bold red]CRITICAL findings detected — exit code 2[/]")
    elif report.exit_code == 1:
        console.print("\n[bold red]HIGH findings detected — exit code 1[/]")
    else:
        console.print("\n[bold green]No HIGH/CRITICAL findings — exit code 0[/]")
    console.print()
