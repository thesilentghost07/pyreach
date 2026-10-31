"""
tests/test_cli.py
~~~~~~~~~~~~~~~~~
Unit and integration tests for backend.cli:
  - Markdown executive report generation (header bar, high-density table,
    collapsible deep-dive traces, remediation commands)
  - JSON report generation (schema validation, aliased evidence keys)
  - Exit code handling (default exit 0 vs --fail-on-reachable exit 1)
  - File output handling (--output flag)
  - Target resolution (fixture defaults vs fallback)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from backend.cli import (
    DEFAULT_FIXTURES,
    format_json_report,
    format_markdown_report,
    main,
    render_markdown_report,
    resolve_targets,
    scan_directory,
)
from backend.schemas import (
    Finding,
    ScanReport,
    ScanSummary,
    Verdict,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REACHABLE_FIXTURE = "tests/fixtures/reachable_app"
NOT_REACHABLE_FIXTURE = "tests/fixtures/not_reachable_app"
UNCERTAIN_FIXTURE = "tests/fixtures/uncertain_app"


# ---------------------------------------------------------------------------
# Tests: Target Resolution
# ---------------------------------------------------------------------------


class TestTargetResolution:
    def test_explicit_targets_preserved(self) -> None:
        explicit = ["tests/fixtures/reachable_app", "custom/path"]
        assert resolve_targets(explicit) == explicit

    def test_default_fixtures_resolved_when_present(self) -> None:
        targets = resolve_targets([])
        assert targets == DEFAULT_FIXTURES

    def test_fallback_to_dot_when_fixtures_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate missing fixtures
        monkeypatch.setattr("backend.cli.DEFAULT_FIXTURES", ["nonexistent/dir/123"])
        targets = resolve_targets([])
        assert targets == ["."]


# ---------------------------------------------------------------------------
# Tests: Markdown Formatting
# ---------------------------------------------------------------------------


class TestMarkdownFormatting:
    @pytest.fixture
    def fixture_reports(self) -> List[ScanReport]:
        return [
            scan_directory(Path(REACHABLE_FIXTURE), use_network=False),
            scan_directory(Path(NOT_REACHABLE_FIXTURE), use_network=False),
            scan_directory(Path(UNCERTAIN_FIXTURE), use_network=False),
        ]

    def test_executive_header_and_performance_bar(self, fixture_reports: List[ScanReport]) -> None:
        md = format_markdown_report(fixture_reports, duration_ms=4.5)

        assert "## 🛡️ PyReach Vulnerability Reachability Report" in md
        assert "> **Static AST Reachability Engine** • Scanned in `4.5ms` • Mode: `Deterministic Static Graph (Zero Code Execution)`" in md
        assert "| 📦 Dependencies Analyzed | 🚨 Advisories Evaluated | 🔴 Confirmed Reachable | 🟢 Suppressed (Not Reachable) | 🟡 Dynamic Hazards |" in md
        assert "| **3** | **3** | **1** | **1** | **1** |" in md

    def test_markdown_table_columns_present(self, fixture_reports: List[ScanReport]) -> None:
        md = format_markdown_report(fixture_reports)

        header = "| Target & Version | Advisory ID | Verdict | Executive Summary |"
        assert header in md

    def test_verdict_badges_rendered(self, fixture_reports: List[ScanReport]) -> None:
        md = format_markdown_report(fixture_reports)

        assert "🔴 REACHABLE" in md
        assert "🟢 NOT_REACHABLE" in md
        assert "🟡 UNCERTAIN" in md

    def test_executive_summaries_rendered(self, fixture_reports: List[ScanReport]) -> None:
        md = format_markdown_report(fixture_reports)

        assert "Direct execution path detected to `yaml.load`" in md
        assert "No static call chain to unsafe sinks" in md
        assert "Dynamic reflection (`getattr`) detected" in md

    def test_collapsible_evidence_traces_rendered(self, fixture_reports: List[ScanReport]) -> None:
        md = format_markdown_report(fixture_reports)

        # Reachable trace
        assert "<details>" in md
        assert "<summary>🔍 <b>View Call Trace: pyyaml (app.run ➔ yaml.load)</b></summary>" in md
        assert "[Hop 1] Entry Point : app.py:4  ➔ def run()" in md
        assert "[Hop 2] Call Site   : app.py:4  ➔ yaml.load(\"payload: true\")" in md
        assert "[Hop 3] Target Sink : yaml.load (arbitrary code execution hazard)" in md

        # Uncertain trace
        assert "<summary>⚠️ <b>Hazard Details: Dynamic Invocation Detected</b></summary>" in md
        assert "- **Hazard Type:** Dynamic attribute lookup (`getattr`)" in md
        assert "- **Source Location:** `app.py:4`" in md
        assert "- **Rationale:** Static call graph resolution conservatively suspended to avoid false negative guarantees. Manual inspection recommended." in md

    def test_remediation_callout_present_for_reachable(self, fixture_reports: List[ScanReport]) -> None:
        md = format_markdown_report(fixture_reports)

        assert "### 🛠️ Recommended Remediation Actions" in md
        assert 'pip install --upgrade "pyyaml>=5.4"' in md
        assert "yaml.safe_load" in md

    def test_remediation_callout_absent_when_no_reachable(self) -> None:
        clean_report = scan_directory(Path(NOT_REACHABLE_FIXTURE), use_network=False)
        md = format_markdown_report([clean_report])

        assert "### 🛠️ Recommended Remediation Actions" not in md
        assert "🟢 NOT_REACHABLE" in md
        assert "No static call chain to unsafe sinks" in md

    def test_empty_findings_handled_cleanly(self) -> None:
        empty_report = ScanReport(
            project="empty_proj",
            scanned_at="2026-10-31T00:00:00Z",
            summary=ScanSummary(
                total_dependencies=0,
                total_advisories=0,
                reachable_count=0,
                not_reachable_count=0,
                uncertain_count=0,
            ),
            dependencies=[],
            findings=[],
            warnings=[],
        )
        md = format_markdown_report([empty_report])
        assert "No vulnerability advisories matched for scanned dependencies." in md

    def test_render_markdown_report_alias(self, fixture_reports: List[ScanReport]) -> None:
        md1 = format_markdown_report(fixture_reports, duration_ms=10.0)
        md2 = render_markdown_report(fixture_reports, duration_ms=10.0)
        assert md1 == md2


# ---------------------------------------------------------------------------
# Tests: JSON Formatting
# ---------------------------------------------------------------------------


class TestJsonFormatting:
    def test_single_target_json_schema(self) -> None:
        report = scan_directory(Path(REACHABLE_FIXTURE), use_network=False)
        json_str = format_json_report([report])

        data = json.loads(json_str)
        assert isinstance(data, dict)
        assert data["project"] == REACHABLE_FIXTURE
        assert data["summary"]["reachable_count"] == 1
        assert len(data["findings"]) == 1

        finding = data["findings"][0]
        assert finding["verdict"] == "REACHABLE"
        assert finding["vulnerable_symbol"] == "yaml.load"

        # Evidence must use "from" and "to" (aliased serialization)
        assert len(finding["evidence"]) == 1
        assert "from" in finding["evidence"][0]
        assert "to" in finding["evidence"][0]
        assert "from_symbol" not in finding["evidence"][0]

    def test_multiple_targets_json_array(self) -> None:
        reports = [
            scan_directory(Path(REACHABLE_FIXTURE), use_network=False),
            scan_directory(Path(NOT_REACHABLE_FIXTURE), use_network=False),
        ]
        json_str = format_json_report(reports)

        data = json.loads(json_str)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["summary"]["reachable_count"] == 1
        assert data[1]["summary"]["reachable_count"] == 0


# ---------------------------------------------------------------------------
# Tests: Exit Code & CLI Execution
# ---------------------------------------------------------------------------


class TestCLIExecution:
    def test_default_exit_code_zero_even_with_reachable(self, capsys: pytest.CaptureFixture) -> None:
        code = main([REACHABLE_FIXTURE])
        assert code == 0

        out = capsys.readouterr().out
        assert "## 🛡️ PyReach Vulnerability Reachability Report" in out
        assert "🔴 REACHABLE" in out

    def test_fail_on_reachable_exits_one_when_reachable_found(self) -> None:
        code = main([REACHABLE_FIXTURE, "--fail-on-reachable"])
        assert code == 1

    def test_fail_on_reachable_exits_zero_when_not_reachable(self) -> None:
        code = main([NOT_REACHABLE_FIXTURE, "--fail-on-reachable"])
        assert code == 0

    def test_fail_on_reachable_exits_zero_when_uncertain(self) -> None:
        code = main([UNCERTAIN_FIXTURE, "--fail-on-reachable"])
        assert code == 0

    def test_output_file_written(self, tmp_path: Path) -> None:
        out_file = tmp_path / "custom_report.md"
        code = main([NOT_REACHABLE_FIXTURE, "-o", str(out_file)])
        assert code == 0
        assert out_file.is_file()

        content = out_file.read_text(encoding="utf-8")
        assert "## 🛡️ PyReach Vulnerability Reachability Report" in content
        assert "🟢 NOT_REACHABLE" in content

    def test_output_file_json_written(self, tmp_path: Path) -> None:
        out_file = tmp_path / "report.json"
        code = main([UNCERTAIN_FIXTURE, "--format", "json", "-o", str(out_file)])
        assert code == 0
        assert out_file.is_file()

        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["findings"][0]["verdict"] == "UNCERTAIN"

    def test_invalid_target_exits_one(self, capsys: pytest.CaptureFixture) -> None:
        code = main(["nonexistent/path/999999"])
        assert code == 1
        err = capsys.readouterr().err
        assert "does not exist" in err
