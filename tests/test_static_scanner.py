from __future__ import annotations

import json
import zipfile
from pathlib import Path

import backend
from hexis.scanner.static import StaticScanner, scan_directory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNSERVERS = PROJECT_ROOT / "vulnservers"
PROMPT_SERVER = VULNSERVERS / "prompt_injection_server.py"
EXPECTED_RULE_IDS = {
    "HEXIS-AUTH-001",
    "HEXIS-AUTH-002",
    "HEXIS-CMD-001",
    "HEXIS-CMD-002",
    "HEXIS-CMD-003",
    "HEXIS-PI-001",
    "HEXIS-PI-002",
    "HEXIS-PI-003",
    "HEXIS-RES-001",
    "HEXIS-RES-002",
    "HEXIS-SSRF-001",
    "HEXIS-SSRF-002",
    "HEXIS-SSRF-003",
    "HEXIS-TLS-001",
}


def test_scan_directory_matches_target_fixture_counts() -> None:
    report = scan_directory(str(VULNSERVERS), include_fixes=True)
    rule_ids = {finding.rule_id for finding in report.findings}

    assert report.scan_mode == "static"
    assert report.summary == {
        "CRITICAL": 6,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 21,
    }
    assert rule_ids == EXPECTED_RULE_IDS


def test_scan_directory_without_fixes_strips_suggestions() -> None:
    report = scan_directory(str(VULNSERVERS), include_fixes=False)
    assert all(finding.fix_suggestion is None for finding in report.findings)


def test_scan_directory_with_fixes_populates_suggestions() -> None:
    report = scan_directory(str(VULNSERVERS), include_fixes=True)
    assert all(finding.fix_suggestion for finding in report.findings)


def test_scan_directory_returns_empty_report_for_missing_target() -> None:
    report = scan_directory("does-not-exist")
    assert report.findings == []
    assert report.summary["TOTAL"] == 0


def test_scan_directory_can_scan_single_file() -> None:
    report = scan_directory(str(PROMPT_SERVER), include_fixes=True)
    rule_ids = {finding.rule_id for finding in report.findings}

    assert report.summary == {
        "CRITICAL": 0,
        "HIGH": 3,
        "MEDIUM": 1,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 4,
    }
    assert rule_ids == {"HEXIS-PI-001", "HEXIS-PI-002", "HEXIS-PI-003"}


def test_scan_directory_reads_json_config_findings(tmp_path: Path) -> None:
    config = {
        "transport": {"type": "streamable-http"},
        "endpoint": "http://prod.example.com/mcp",
        "tools": [
            {
                "name": "fetch_file",
                "description": "Safe helper.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "path": {"type": "string"},
                    },
                },
            }
        ],
    }
    (tmp_path / "server.json").write_text(json.dumps(config), encoding="utf-8")

    report = scan_directory(str(tmp_path), include_fixes=True)
    rule_ids = {finding.rule_id for finding in report.findings}

    assert rule_ids == {"HEXIS-AUTH-001", "HEXIS-RES-001", "HEXIS-SSRF-001", "HEXIS-TLS-001"}
    assert report.summary == {
        "CRITICAL": 0,
        "HIGH": 4,
        "MEDIUM": 2,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 6,
    }


def test_scan_directory_ignores_virtualenv_dirs(tmp_path: Path) -> None:
    ignored_dir = tmp_path / ".venv"
    ignored_dir.mkdir()
    (ignored_dir / "bad.py").write_text(
        'import httpx\ndef call_tool(url):\n    return httpx.get(url)\n',
        encoding="utf-8",
    )
    (tmp_path / "safe.py").write_text("value = 1\n", encoding="utf-8")

    report = scan_directory(str(tmp_path), include_fixes=True)
    assert report.summary["TOTAL"] == 0


def test_static_scanner_wrapper_matches_function_result() -> None:
    wrapper_report = StaticScanner().scan(str(VULNSERVERS), include_fixes=True)
    direct_report = scan_directory(str(VULNSERVERS), include_fixes=True)

    assert wrapper_report.summary == direct_report.summary
    assert [finding.rule_id for finding in wrapper_report.findings] == [
        finding.rule_id for finding in direct_report.findings
    ]


def test_build_wheel_includes_package_files(tmp_path: Path) -> None:
    wheel_name = backend.build_wheel(str(tmp_path))
    wheel_path = tmp_path / wheel_name

    with zipfile.ZipFile(wheel_path) as archive:
        names = set(archive.namelist())

    assert "hexis/__init__.py" in names
    assert any(name.endswith(".dist-info/METADATA") for name in names)


def test_build_editable_includes_path_file(tmp_path: Path) -> None:
    wheel_name = backend.build_editable(str(tmp_path))
    wheel_path = tmp_path / wheel_name

    with zipfile.ZipFile(wheel_path) as archive:
        names = archive.namelist()
        pth_files = [name for name in names if name.endswith(".pth")]
        pth_text = archive.read(pth_files[0]).decode("utf-8")

    assert pth_files
    assert str(PROJECT_ROOT) in pth_text
    assert "hexis/__init__.py" not in names
