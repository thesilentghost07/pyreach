"""
test_deps_advisory.py — Tests for Member 3 (Nischay)

Tests the requirements.txt parser, offline symbol_map.json matching,
mocked OSV API responses, network failure fallback, and FastAPI endpoints.

ALL mocks and synthetic data are explicitly labelled.
NO test makes a real network call.
NO test executes scanned project code.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

# Ensure repo root is on sys.path for direct pytest invocation
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import pytest

from backend.deps_advisory import resolve_dependencies_and_advisories
from backend.schemas import ScanReport, Verdict


# ===================================================================
# Helper: write a temporary requirements.txt inside a temp dir
# ===================================================================

def _make_project(tmp_path: Path, req_contents: str) -> Path:
    """Create a minimal project dir with a requirements.txt."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(req_contents, encoding="utf-8")
    return tmp_path


# ===================================================================
# 1. REQUIREMENTS PARSING — basic pinned / unpinned / comments
# ===================================================================


class TestRequirementsParsing:
    """Test that requirements.txt lines are parsed correctly."""

    def test_pinned_dependency(self, tmp_path: Path):
        """pyyaml==5.3.1 should be pinned with exact version."""
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "pyyaml"
        assert deps[0].version == "5.3.1"
        assert deps[0].is_pinned is True
        assert deps[0].source_file == "requirements.txt"
        assert deps[0].line == 1

    def test_unpinned_dependency(self, tmp_path: Path):
        """requests>=2.0 should NOT be pinned."""
        proj = _make_project(tmp_path, "requests>=2.0\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].is_pinned is False
        assert deps[0].version is None

    def test_comments_and_blanks_ignored(self, tmp_path: Path):
        """Blank lines and # comments produce no dependencies."""
        proj = _make_project(tmp_path, "# this is a comment\n\n\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)
        assert deps == []

    def test_inline_comment_stripped(self, tmp_path: Path):
        """pyyaml==5.3.1 # config parser -> should parse correctly."""
        proj = _make_project(tmp_path, "pyyaml==5.3.1 # config parser\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "pyyaml"
        assert deps[0].version == "5.3.1"
        assert deps[0].is_pinned is True

    def test_bare_package_name(self, tmp_path: Path):
        """Click (bare, no version) -> name='click', unpinned, version=None."""
        proj = _make_project(tmp_path, "Click\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "click"
        assert deps[0].is_pinned is False
        assert deps[0].version is None

    def test_name_normalisation(self, tmp_path: Path):
        """PyYAML -> pyyaml, my_pkg.name -> my-pkg-name."""
        proj = _make_project(tmp_path, "PyYAML==5.3.1\nmy_pkg.name==1.0\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert deps[0].name == "pyyaml"
        assert deps[1].name == "my-pkg-name"

    def test_extras_stripped(self, tmp_path: Path):
        """uvicorn[standard]==0.20.0 -> name='uvicorn', version='0.20.0', pinned."""
        proj = _make_project(tmp_path, "uvicorn[standard]==0.20.0\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "uvicorn"
        assert deps[0].version == "0.20.0"
        assert deps[0].is_pinned is True

    def test_environment_markers_stripped(self, tmp_path: Path):
        """colorama==0.4.6; sys_platform == 'win32' -> parsed correctly."""
        proj = _make_project(
            tmp_path, 'colorama==0.4.6; sys_platform == "win32"\n'
        )
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "colorama"
        assert deps[0].version == "0.4.6"
        assert deps[0].is_pinned is True

    def test_triple_equals_pinned(self, tmp_path: Path):
        """requests===2.25.1 uses === which counts as pinned."""
        proj = _make_project(tmp_path, "requests===2.25.1\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.25.1"
        assert deps[0].is_pinned is True

    def test_line_numbers_correct(self, tmp_path: Path):
        """Line numbers must be exact 1-based positions in the file."""
        proj = _make_project(tmp_path, "# header\npyyaml==5.3.1\n\nflask>=2.0\n")
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 2
        assert deps[0].line == 2  # pyyaml is on line 2
        assert deps[1].line == 4  # flask is on line 4

    def test_r_flag_produces_warning(self, tmp_path: Path):
        """-r other.txt should be skipped with a warning."""
        proj = _make_project(tmp_path, "-r other.txt\npyyaml==5.3.1\n")
        deps, _, warnings = resolve_dependencies_and_advisories(
            proj, use_network=False
        )

        assert len(deps) == 1  # only pyyaml parsed
        assert any("-r" in w for w in warnings)

    def test_missing_requirements_txt(self, tmp_path: Path):
        """Missing file -> empty deps, no crash, warning emitted."""
        deps, advs, warnings = resolve_dependencies_and_advisories(
            tmp_path, use_network=False
        )

        assert deps == []
        assert advs == []
        assert any("No requirements.txt" in w for w in warnings)

    def test_various_operators_unpinned(self, tmp_path: Path):
        """~=, !=, >, <, <= operators -> unpinned."""
        content = "flask~=2.0\nurllib3!=1.25.0\nsix<2.0\n"
        proj = _make_project(tmp_path, content)
        deps, _, _ = resolve_dependencies_and_advisories(proj, use_network=False)

        assert len(deps) == 3
        for d in deps:
            assert d.is_pinned is False


# ===================================================================
# 2. OFFLINE symbol_map.json MATCHING
# ===================================================================


class TestOfflineSymbolMap:
    """Test matching against the curated symbol_map.json."""

    def test_pyyaml_offline_match(self, tmp_path: Path):
        """pyyaml==5.3.1 offline -> PYSEC-2020-96 with curated symbols."""
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")
        _, advisories, _ = resolve_dependencies_and_advisories(
            proj, use_network=False
        )

        assert len(advisories) == 1
        adv = advisories[0]
        assert adv.advisory_id == "PYSEC-2020-96"
        assert adv.symbol_source == "curated_map"
        assert "yaml.load" in adv.vulnerable_symbols
        assert "yaml.unsafe_load" in adv.vulnerable_symbols
        assert "yaml.full_load" in adv.vulnerable_symbols

    def test_demo_vuln_pkg_offline_match(self, tmp_path: Path):
        """demo-vuln-pkg==1.0.0 -> SYNTHETIC-DEMO-001, synthetic entry."""
        proj = _make_project(tmp_path, "demo-vuln-pkg==1.0.0\n")
        _, advisories, _ = resolve_dependencies_and_advisories(
            proj, use_network=False
        )

        assert len(advisories) == 1
        adv = advisories[0]
        assert adv.advisory_id == "SYNTHETIC-DEMO-001"
        assert adv.vulnerable_symbols == ["demo_vuln_pkg.unsafe_exec"]
        assert adv.summary.startswith(
            "SYNTHETIC DEMO ADVISORY (not a real vulnerability):"
        )

    def test_unknown_package_no_match(self, tmp_path: Path):
        """nonexistent-pkg==0.0.1 offline -> no advisory."""
        proj = _make_project(tmp_path, "nonexistent-pkg==0.0.1\n")
        _, advisories, _ = resolve_dependencies_and_advisories(
            proj, use_network=False
        )
        assert advisories == []


# ===================================================================
# 3. MOCKED OSV RESPONSE PARSING
# ===================================================================


class TestMockedOSV:
    """Test OSV response parsing with MOCKED data (no real network calls)."""

    # MOCKED OSV RESPONSE: vulnerability WITH ecosystem_specific symbols
    MOCK_OSV_WITH_SYMBOLS = {
        "vulns": [
            {
                "id": "PYSEC-2020-96",
                "summary": "MOCKED: Arbitrary code execution in PyYAML",
                "aliases": ["CVE-2020-14343"],
                "affected": [
                    {
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "5.4"},
                                ]
                            }
                        ],
                        "ecosystem_specific": {
                            "imports": [
                                {
                                    "path": "yaml",
                                    "symbols": ["load", "unsafe_load"],
                                }
                            ]
                        },
                    }
                ],
            }
        ]
    }

    # MOCKED OSV RESPONSE: vulnerability WITHOUT symbols, NOT in symbol_map
    MOCK_OSV_NO_SYMBOLS_UNKNOWN = {
        "vulns": [
            {
                "id": "PYSEC-9999-FAKE",
                "summary": "MOCKED: Some other vulnerability",
                "aliases": [],
                "affected": [
                    {
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "99.0"},
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }

    # MOCKED OSV RESPONSE: vulnerability WITHOUT symbols for pyyaml
    # (should fall back to symbol_map.json enrichment)
    MOCK_OSV_NO_SYMBOLS_PYYAML = {
        "vulns": [
            {
                "id": "PYSEC-2020-96",
                "summary": "MOCKED: PyYAML vuln without symbols from OSV",
                "aliases": ["CVE-2020-14343"],
                "affected": [
                    {
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "5.4"},
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }

    @patch("backend.deps_advisory._query_osv_api")
    def test_osv_with_symbols(self, mock_osv, tmp_path: Path):
        """OSV returns symbols -> symbol_source='osv_imports'."""
        mock_osv.return_value = self.MOCK_OSV_WITH_SYMBOLS  # MOCKED
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")

        _, advisories, _ = resolve_dependencies_and_advisories(
            proj, use_network=True
        )

        # Should find the OSV advisory with symbols
        osv_adv = [a for a in advisories if a.symbol_source == "osv_imports"]
        assert len(osv_adv) >= 1
        assert "yaml.load" in osv_adv[0].vulnerable_symbols
        assert "yaml.unsafe_load" in osv_adv[0].vulnerable_symbols

    @patch("backend.deps_advisory._query_osv_api")
    def test_osv_no_symbols_unknown_pkg(self, mock_osv, tmp_path: Path):
        """OSV returns a vuln with no symbols for unknown pkg -> symbol_source='none'."""
        mock_osv.return_value = self.MOCK_OSV_NO_SYMBOLS_UNKNOWN  # MOCKED
        proj = _make_project(tmp_path, "somepkg==1.0.0\n")

        _, advisories, _ = resolve_dependencies_and_advisories(
            proj, use_network=True
        )

        assert len(advisories) >= 1
        adv = advisories[0]
        assert adv.vulnerable_symbols == []
        assert adv.symbol_source == "none"

    @patch("backend.deps_advisory._query_osv_api")
    def test_osv_no_symbols_falls_back_to_symbol_map(
        self, mock_osv, tmp_path: Path
    ):
        """OSV returns pyyaml vuln without symbols -> enriched from symbol_map.json."""
        mock_osv.return_value = self.MOCK_OSV_NO_SYMBOLS_PYYAML  # MOCKED
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")

        _, advisories, _ = resolve_dependencies_and_advisories(
            proj, use_network=True
        )

        pysec_adv = [a for a in advisories if a.advisory_id == "PYSEC-2020-96"]
        assert len(pysec_adv) >= 1
        assert pysec_adv[0].symbol_source == "curated_map"
        assert "yaml.load" in pysec_adv[0].vulnerable_symbols


# ===================================================================
# 4. NETWORK FAILURE / TIMEOUT FALLBACK
# ===================================================================


class TestNetworkFailureFallback:
    """Verify graceful fallback when OSV is unreachable."""

    @patch("backend.deps_advisory._query_osv_api")
    def test_url_error_fallback(self, mock_osv, tmp_path: Path):
        """URLError -> warning appended, pyyaml still matched offline."""
        mock_osv.side_effect = urllib.error.URLError(
            "mocked network error"  # MOCKED
        )
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")

        _, advisories, warnings = resolve_dependencies_and_advisories(
            proj, use_network=True
        )

        # Should NOT crash
        assert any("OSV lookup failed" in w for w in warnings)
        # Should still match offline
        assert len(advisories) >= 1
        assert advisories[0].advisory_id == "PYSEC-2020-96"
        assert advisories[0].symbol_source == "curated_map"

    @patch("backend.deps_advisory._query_osv_api")
    def test_timeout_error_fallback(self, mock_osv, tmp_path: Path):
        """TimeoutError -> warning appended, offline fallback works."""
        mock_osv.side_effect = TimeoutError("mocked timeout")  # MOCKED
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")

        _, advisories, warnings = resolve_dependencies_and_advisories(
            proj, use_network=True
        )

        assert any("OSV lookup failed" in w for w in warnings)
        assert len(advisories) >= 1
        assert advisories[0].symbol_source == "curated_map"


# ===================================================================
# 5. use_network=False — NO HTTP CALL MADE
# ===================================================================


class TestNetworkDisabled:
    """Verify that use_network=False never calls the OSV helper."""

    @patch("backend.deps_advisory._query_osv_api")
    def test_no_http_when_network_disabled(self, mock_osv, tmp_path: Path):
        """With use_network=False, _query_osv_api must NOT be called."""
        proj = _make_project(tmp_path, "pyyaml==5.3.1\n")

        _, _, warnings = resolve_dependencies_and_advisories(
            proj, use_network=False
        )

        mock_osv.assert_not_called()  # Zero calls
        assert any("Network disabled" in w for w in warnings)


# ===================================================================
# 6. FASTAPI ENDPOINT TESTS (TestClient, no real server needed)
# ===================================================================


class TestFastAPIEndpoints:
    """Test the FastAPI endpoints using httpx TestClient.

    Member 1 (ast_scanner) and Member 2 (reachability) are monkeypatched
    with MOCKED stubs so these tests work independently.
    """

    @pytest.fixture()
    def client(self):
        """Create a TestClient for the FastAPI app."""
        from fastapi.testclient import TestClient

        from backend.main import app

        return TestClient(app)

    def test_health_check(self, client):
        """GET /api/health -> 200, {"status": "ok"}."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_fixtures_returns_list(self, client):
        """GET /api/fixtures -> 200, returns a list of strings."""
        resp = client.get("/api/fixtures")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # Every item should be a string (relative path)
        for item in data:
            assert isinstance(item, str)

    def test_scan_nonexistent_path_400(self, client):
        """POST /api/scan with a non-existent path -> 400."""
        resp = client.post(
            "/api/scan",
            json={"project_path": "does/not/exist", "use_network": False},
        )
        assert resp.status_code == 400

    def test_scan_path_traversal_400(self, client):
        """POST /api/scan with path traversal -> 400."""
        resp = client.post(
            "/api/scan",
            json={"project_path": "../../etc", "use_network": False},
        )
        assert resp.status_code == 400

    def test_scan_empty_path_400(self, client):
        """POST /api/scan with empty project_path -> 400."""
        resp = client.post(
            "/api/scan",
            json={"project_path": "   ", "use_network": False},
        )
        assert resp.status_code == 400

    def test_scan_full_pipeline_mocked(self, client, tmp_path: Path, monkeypatch):
        """POST /api/scan with MOCKED ast_scanner and reachability -> 200.

        Validates that the response is a valid ScanReport with EvidenceStep
        serialized using 'from' and 'to' keys (by_alias=True).
        """
        import backend.main as main_module
        from backend.schemas import (
            CallSite,
            EvidenceStep,
            Finding,
            FunctionDefRecord,
            ImportRecord,
            ParsedFile,
            ProjectASTResult,
            ScanReport,
            Verdict,
        )

        # --- Create a temporary project dir INSIDE the repo root ---
        # We need a dir inside REPO_ROOT for path-traversal checks to pass.
        scan_dir = main_module.REPO_ROOT / "_tmp_test_scan"
        scan_dir.mkdir(exist_ok=True)
        req_file = scan_dir / "requirements.txt"
        req_file.write_text("pyyaml==5.3.1\n", encoding="utf-8")
        app_file = scan_dir / "app.py"
        app_file.write_text("import yaml\nyaml.load('x')\n", encoding="utf-8")

        try:
            # MOCKED: Member 1 ast_scanner returns a fake ProjectASTResult
            fake_ast = ProjectASTResult(
                project_path=str(scan_dir),
                files=[
                    ParsedFile(
                        file_path="app.py",
                        imports=[
                            ImportRecord(
                                module="yaml",
                                imported_name=None,
                                alias="yaml",
                                file="app.py",
                                line=1,
                            )
                        ],
                        functions=[
                            FunctionDefRecord(
                                qualname="<module>",
                                name="<module>",
                                file="app.py",
                                line=1,
                                is_entry_point=True,
                            )
                        ],
                        calls=[
                            CallSite(
                                caller_qualname="<module>",
                                raw_callee="yaml.load",
                                resolved_callee="yaml.load",
                                file="app.py",
                                line=2,
                            )
                        ],
                    )
                ],
                entry_points=["<module>"],
            )

            # MOCKED: Member 2 reachability returns a fake Finding
            fake_finding = Finding(
                package="pyyaml",
                installed_version="5.3.1",
                advisory_id="PYSEC-2020-96",
                summary="MOCKED finding for test",
                verdict=Verdict.REACHABLE,
                confidence="high",
                vulnerable_symbol="yaml.load",
                evidence=[
                    EvidenceStep(
                        from_symbol="app.main",
                        to_symbol="yaml.load",
                        file="app.py",
                        line=10,
                    )
                ],
                reason="MOCKED: Direct call to yaml.load found",
            )

            # Monkeypatch Member 1 and Member 2
            monkeypatch.setattr(
                main_module, "scan_project_ast", lambda p: fake_ast
            )
            monkeypatch.setattr(
                main_module,
                "analyze_reachability",
                lambda ast_r, advs: [fake_finding],
            )

            resp = client.post(
                "/api/scan",
                json={
                    "project_path": "_tmp_test_scan",
                    "use_network": False,
                },
            )

            assert resp.status_code == 200
            data = resp.json()

            # Validate full report structure
            report = ScanReport.model_validate(data)
            assert report.project == "_tmp_test_scan"
            assert report.summary.total_dependencies >= 1
            assert report.summary.reachable_count == 1
            assert len(report.findings) == 1

            # Verify EvidenceStep serialized with "from" and "to" keys
            finding_json = data["findings"][0]
            assert len(finding_json["evidence"]) == 1
            ev = finding_json["evidence"][0]
            assert "from" in ev, "EvidenceStep must serialize with 'from' key"
            assert "to" in ev, "EvidenceStep must serialize with 'to' key"
            assert ev["from"] == "app.main"
            assert ev["to"] == "yaml.load"

        finally:
            # Clean up temporary dir
            if app_file.exists():
                app_file.unlink()
            if req_file.exists():
                req_file.unlink()
            if scan_dir.exists():
                scan_dir.rmdir()

    def test_scan_full_pipeline_real_ast_and_reachability(self, client):
        """End-to-end integration test of /api/scan using real AST scanner

        and real reachability engine (without mocks for Member 1 & 2).
        """
        scan_dir = _repo_root / "_tmp_real_integration_scan"
        scan_dir.mkdir(exist_ok=True)
        req_file = scan_dir / "requirements.txt"
        app_file = scan_dir / "main.py"

        req_file.write_text("pyyaml==5.3.1\n", encoding="utf-8")
        app_file.write_text(
            "import yaml\n\n"
            "def main():\n"
            "    yaml.load('foo')\n",
            encoding="utf-8",
        )

        try:
            resp = client.post(
                "/api/scan",
                json={
                    "project_path": "_tmp_real_integration_scan",
                    "use_network": False,
                },
            )

            assert resp.status_code == 200
            data = resp.json()
            report = ScanReport.model_validate(data)

            assert report.project == "_tmp_real_integration_scan"
            assert report.summary.total_dependencies == 1
            assert report.summary.total_advisories == 1
            assert report.summary.reachable_count == 1
            assert len(report.findings) == 1
            assert report.findings[0].verdict == Verdict.REACHABLE
            assert report.findings[0].package == "pyyaml"
        finally:
            if app_file.exists():
                app_file.unlink()
            if req_file.exists():
                req_file.unlink()
            if scan_dir.exists():
                scan_dir.rmdir()
