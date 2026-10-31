"""
Comprehensive edge-case tests for PyReach reachability engine.

Tests 6 challenging real-world Python patterns against the static analysis
pipeline to verify engine resilience:
  1. Aliased import resolution
  2. Uncalled dead-code suppression
  3. Cross-file multi-hop call chains
  4. Cyclic recursion graph termination
  5. Nested closure reachability
  6. Dynamic eval/reflection hazard detection

All expected verdicts were probed against the actual engine prior to assertion
authoring — no values are fabricated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.ast_scanner import scan_project_ast
from backend.deps_advisory import resolve_dependencies_and_advisories
from backend.reachability import analyze_reachability
from backend.schemas import Verdict

# ── Helpers ──────────────────────────────────────────────────────────────

EDGE_CASES_DIR = Path(__file__).resolve().parent / "fixtures" / "edge_cases"


def _run_pipeline(fixture_name: str):
    """Run the full scan pipeline on a named edge-case fixture directory.

    Returns (findings, ast_result, advisories, warnings).
    """
    fixture_dir = EDGE_CASES_DIR / fixture_name
    deps, advisories, warnings = resolve_dependencies_and_advisories(
        fixture_dir, use_network=False
    )
    ast_result = scan_project_ast(fixture_dir)
    findings = analyze_reachability(ast_result, advisories)
    return findings, ast_result, advisories, warnings


# ── Edge Case 1: Aliased Import Resolution ───────────────────────────────


class TestAliasedImportResolution:
    """from yaml import load as untrusted_parser → must resolve to yaml.load."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.findings, self.ast_result, *_ = _run_pipeline("aliased_import")
        assert len(self.findings) == 1
        self.finding = self.findings[0]

    def test_verdict_is_reachable(self):
        assert self.finding.verdict == Verdict.REACHABLE

    def test_confidence_is_high(self):
        assert self.finding.confidence == "high"

    def test_vulnerable_symbol_is_yaml_load(self):
        assert self.finding.vulnerable_symbol == "yaml.load"

    def test_evidence_chain_resolves_alias(self):
        """The evidence must show the resolved callee yaml.load, not the alias."""
        assert len(self.finding.evidence) >= 1
        last_step = self.finding.evidence[-1]
        assert last_step.to_symbol == "yaml.load"

    def test_alias_appears_in_call_sites(self):
        """The AST scanner should record the raw callee as 'untrusted_parser'
        and the resolved callee as 'yaml.load'."""
        calls = [
            c
            for pf in self.ast_result.files
            for c in pf.calls
            if c.raw_callee == "untrusted_parser"
        ]
        assert len(calls) >= 1
        assert calls[0].resolved_callee == "yaml.load"


# ── Edge Case 2: Uncalled Sink Suppression ───────────────────────────────


class TestUncalledSinkSuppression:
    """yaml.load exists in unused_legacy_importer but is never called from
    any entry point — BFS must not reach it."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.findings, self.ast_result, *_ = _run_pipeline("uncalled_sink")
        assert len(self.findings) == 1
        self.finding = self.findings[0]

    def test_verdict_is_not_reachable(self):
        assert self.finding.verdict == Verdict.NOT_REACHABLE

    def test_confidence_is_medium(self):
        assert self.finding.confidence == "medium"

    def test_no_evidence_path(self):
        assert self.finding.evidence == []

    def test_vulnerable_call_exists_in_ast(self):
        """Confirm the vulnerable call IS present in the AST (just unreachable)."""
        all_callees = [
            c.resolved_callee or c.raw_callee
            for pf in self.ast_result.files
            for c in pf.calls
        ]
        assert "yaml.load" in all_callees

    def test_unused_function_is_not_entry_point(self):
        """unused_legacy_importer must NOT be marked as an entry point."""
        funcs = {
            f.qualname: f
            for pf in self.ast_result.files
            for f in pf.functions
        }
        assert "app.unused_legacy_importer" in funcs
        assert funcs["app.unused_legacy_importer"].is_entry_point is False


# ── Edge Case 3: Cross-File Multi-Hop Chain ──────────────────────────────


class TestCrossFileHopReachability:
    """app.py → service.parse_document → yaml.load across two files."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.findings, self.ast_result, *_ = _run_pipeline("cross_file_hop")
        assert len(self.findings) == 1
        self.finding = self.findings[0]

    def test_verdict_is_reachable(self):
        assert self.finding.verdict == Verdict.REACHABLE

    def test_evidence_spans_multiple_files(self):
        """Evidence steps must reference both app.py and service.py."""
        files_in_evidence = {step.file for step in self.finding.evidence}
        assert "app.py" in files_in_evidence
        assert "service.py" in files_in_evidence

    def test_evidence_has_at_least_two_hops(self):
        assert len(self.finding.evidence) >= 2

    def test_final_hop_targets_yaml_load(self):
        last_step = self.finding.evidence[-1]
        assert last_step.to_symbol == "yaml.load"
        assert last_step.file == "service.py"

    def test_first_hop_is_cross_file_call(self):
        first_step = self.finding.evidence[0]
        assert "parse_document" in first_step.to_symbol


# ── Edge Case 4: Cyclic Recursion BFS Termination ───────────────────────


class TestCyclicRecursionTermination:
    """ping ↔ pong mutual recursion — only yaml.safe_load used.
    BFS must terminate without RecursionError and report NOT_REACHABLE."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.findings, self.ast_result, *_ = _run_pipeline("cyclic_recursion")
        assert len(self.findings) == 1
        self.finding = self.findings[0]

    def test_no_recursion_error(self):
        """If we got here, BFS terminated — the cycle didn't cause infinite loop."""
        assert self.finding.verdict in {
            Verdict.NOT_REACHABLE,
            Verdict.UNCERTAIN,
        }

    def test_verdict_is_not_reachable(self):
        assert self.finding.verdict == Verdict.NOT_REACHABLE

    def test_no_evidence_path(self):
        assert self.finding.evidence == []

    def test_both_recursive_functions_in_ast(self):
        """Both ping and pong must appear in the function definitions."""
        func_names = {
            f.name for pf in self.ast_result.files for f in pf.functions
        }
        assert "ping" in func_names
        assert "pong" in func_names


# ── Edge Case 5: Nested Closure Reachability ─────────────────────────────


class TestNestedClosureReachability:
    """run() → outer_processor() → inner_dispatch() → yaml.load.
    The engine successfully resolves through the nested function."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.findings, self.ast_result, *_ = _run_pipeline("nested_closure")
        assert len(self.findings) == 1
        self.finding = self.findings[0]

    def test_verdict_is_reachable(self):
        assert self.finding.verdict == Verdict.REACHABLE

    def test_confidence_is_high(self):
        assert self.finding.confidence == "high"

    def test_evidence_chain_depth(self):
        """Evidence must show at least 3 hops:
        run → outer_processor → inner_dispatch → yaml.load."""
        assert len(self.finding.evidence) >= 3

    def test_inner_function_appears_in_evidence(self):
        """The inner_dispatch function must appear in the evidence chain."""
        all_symbols = set()
        for step in self.finding.evidence:
            all_symbols.add(step.from_symbol)
            all_symbols.add(step.to_symbol)
        # The inner function qualname uses the module prefix
        inner_refs = [s for s in all_symbols if "inner_dispatch" in s]
        assert len(inner_refs) >= 1


# ── Edge Case 6: Dynamic eval() Reflection Hazard ───────────────────────


class TestDynamicEvalReflectionHazard:
    """eval(f"...") hides the actual yaml.load call from static analysis.
    Engine must conservatively report UNCERTAIN with a dynamic hazard."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.findings, self.ast_result, *_ = _run_pipeline("eval_reflection")
        assert len(self.findings) == 1
        self.finding = self.findings[0]

    def test_verdict_is_uncertain(self):
        assert self.finding.verdict == Verdict.UNCERTAIN

    def test_confidence_is_low(self):
        assert self.finding.confidence == "low"

    def test_has_dynamic_hazard_reason(self):
        """Uncertainty reasons must mention the eval dynamic call hazard."""
        hazard_text = " ".join(self.finding.uncertainty_reasons).lower()
        assert "dynamic" in hazard_text
        assert "eval" in hazard_text

    def test_no_evidence_path(self):
        """Static analysis cannot trace through eval — no evidence expected."""
        assert self.finding.evidence == []

    def test_eval_flagged_as_dynamic_in_ast(self):
        """The AST scanner must flag the eval() call as is_dynamic=True."""
        dynamic_calls = [
            c
            for pf in self.ast_result.files
            for c in pf.calls
            if c.is_dynamic and "eval" in c.raw_callee
        ]
        assert len(dynamic_calls) >= 1
