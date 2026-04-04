from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import hexis.cli as cli_module
import hexis.scanner.dynamic as dynamic_scanner
from hexis import __version__
from hexis.cli import app
from hexis.models import Finding, ScanReport, Severity
from hexis.scanner.dynamic import probe_server

runner = CliRunner()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNSERVERS = PROJECT_ROOT / "vulnservers"


class DummyAsyncClient:
    def __init__(self, *args, **kwargs) -> None:
        del args, kwargs

    async def __aenter__(self) -> DummyAsyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        del exc_type, exc, tb
        return False


def test_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"hexis-mcp-guard v{__version__}"


def test_rules() -> None:
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    assert "HEXIS-SSRF-001" in result.stdout
    assert "Description" in result.stdout
    assert "Any client" in result.stdout
    assert "14 rules loaded" in result.stdout


def test_scan_vulnservers_text_exits_with_critical_status() -> None:
    result = runner.invoke(app, ["scan", str(VULNSERVERS)])

    assert result.exit_code == 2
    assert "CRITICAL findings detected" in result.stdout


def test_scan_vulnservers_json_matches_target_summary() -> None:
    result = runner.invoke(app, ["scan", str(VULNSERVERS), "--format", "json"])
    parsed = json.loads(result.stdout)

    assert result.exit_code == 2
    assert parsed["scan_mode"] == "static"
    assert parsed["summary"] == {
        "CRITICAL": 6,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 21,
    }


def test_scan_rejects_invalid_format() -> None:
    result = runner.invoke(app, ["scan", str(VULNSERVERS), "--format", "xml"])

    assert result.exit_code == 2
    output = result.output
    try:
        output = result.stderr
    except ValueError:
        pass
    assert "Format must be one of: text, json, sarif." in output


def test_scan_fail_on_high_returns_exit_code_one() -> None:
    result = runner.invoke(
        app,
        ["scan", str(VULNSERVERS), "--format", "json", "--fail-on", "high"],
    )

    assert result.exit_code == 1
    assert json.loads(result.stdout)["summary"]["HIGH"] == 10


def test_scan_baseline_suppresses_critical_findings(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            [
                {"rule_id": "HEXIS-CMD-001"},
                {"rule_id": "HEXIS-CMD-002"},
                {"rule_id": "HEXIS-CMD-003"},
                {"rule_id": "HEXIS-SSRF-002"},
                {"rule_id": "HEXIS-SSRF-003"},
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            str(VULNSERVERS),
            "--format",
            "json",
            "--baseline",
            str(baseline_path),
        ],
    )
    parsed = json.loads(result.stdout)

    assert result.exit_code == 1
    assert parsed["summary"]["CRITICAL"] == 0
    assert parsed["summary"]["TOTAL"] == 15


def test_scan_full_mode_merges_dynamic_report(monkeypatch) -> None:
    async def fake_probe(url: str, include_fixes: bool) -> ScanReport:
        del include_fixes
        report = ScanReport(
            tool_version=__version__,
            scan_target=url,
            scan_mode="dynamic",
            duration_seconds=0.05,
            findings=[
                Finding(
                    rule_id="HEXIS-DYN-777",
                    title="Dynamic test finding",
                    description="Injected by test double.",
                    severity=Severity.MEDIUM,
                    score=4.0,
                    category="transport",
                )
            ],
        )
        report.build_summary()
        return report

    monkeypatch.setattr(cli_module, "_probe", fake_probe)
    result = runner.invoke(
        app,
        [
            "scan",
            str(VULNSERVERS),
            "--url",
            "http://localhost:8000/mcp",
            "--dynamic",
            "--format",
            "json",
        ],
    )
    parsed = json.loads(result.stdout)

    assert result.exit_code == 2
    assert parsed["scan_mode"] == "full"
    assert parsed["summary"]["TOTAL"] == 22
    assert parsed["summary"]["MEDIUM"] == 6


@pytest.mark.asyncio
async def test_probe_server_returns_unreachable_info_finding(monkeypatch) -> None:
    async def fake_get_tools(client, url: str):
        del client, url
        return None

    monkeypatch.setattr(dynamic_scanner.httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(dynamic_scanner, "_get_tools", fake_get_tools)

    report = await probe_server("http://localhost:9000/mcp")

    assert report.scan_mode == "dynamic"
    assert report.summary["INFO"] == 1
    assert report.exit_code == 0


@pytest.mark.asyncio
async def test_probe_server_detects_tls_and_ssrf(monkeypatch) -> None:
    async def fake_get_tools(client, url: str):
        del client, url
        return [
            {
                "name": "fetch_url",
                "inputSchema": {
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                    }
                },
            }
        ]

    async def fake_call_tool(client, url: str, tool_name: str, arguments: dict[str, object]):
        del client, url, tool_name, arguments
        return {"result": {"content": [{"type": "text", "text": "safe"}]}}

    monkeypatch.setattr(dynamic_scanner.httpx, "AsyncClient", DummyAsyncClient)
    monkeypatch.setattr(dynamic_scanner, "_get_tools", fake_get_tools)
    monkeypatch.setattr(dynamic_scanner, "_call_tool", fake_call_tool)

    report = await probe_server("http://prod.example.com/mcp", include_fixes=True)
    rule_ids = [finding.rule_id for finding in report.findings]

    assert report.summary["CRITICAL"] == 3
    assert report.summary["MEDIUM"] == 1
    assert rule_ids.count("HEXIS-SSRF-002") == 3
    assert "HEXIS-TLS-001" in rule_ids
    assert all(finding.fix_suggestion is not None for finding in report.findings)


@contextmanager
def run_demo_server(script_name: str) -> Iterator[str]:
    port = _find_free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            str(VULNSERVERS / script_name),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_server(url, process)
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.asyncio
async def test_probe_server_detects_live_auth_gap_when_sockets_available() -> None:
    with run_demo_server("no_auth_server.py") as url:
        report = await probe_server(url, include_fixes=True)

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "HEXIS-AUTH-001" in rule_ids
    assert report.scan_mode == "dynamic"


@pytest.mark.asyncio
async def test_probe_server_detects_live_prompt_metadata_when_sockets_available() -> None:
    with run_demo_server("prompt_injection_server.py") as url:
        report = await probe_server(url, include_fixes=True)

    rule_ids = {finding.rule_id for finding in report.findings}
    assert {"HEXIS-AUTH-001", "HEXIS-PI-001", "HEXIS-PI-003"}.issubset(rule_ids)


@pytest.mark.asyncio
async def test_probe_server_detects_live_shell_injection_when_sockets_available() -> None:
    with run_demo_server("shell_injection_server.py") as url:
        report = await probe_server(url, include_fixes=True)

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "HEXIS-CMD-001" in rule_ids


@pytest.mark.asyncio
async def test_probe_server_detects_live_ssrf_when_sockets_available() -> None:
    with run_demo_server("ssrf_server.py") as url:
        report = await probe_server(url, include_fixes=True)

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "HEXIS-SSRF-002" in rule_ids
    assert "HEXIS-TLS-001" not in rule_ids


def _find_free_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])
    except PermissionError:
        pytest.skip("local socket operations are unavailable in this sandbox")


def _wait_for_server(url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Server exited early with code {process.returncode}: {url}")
        try:
            health = httpx.post(
                url,
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                timeout=0.5,
            )
            if health.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
            continue
        time.sleep(0.1)
    raise RuntimeError(f"Server did not become ready: {url}")
