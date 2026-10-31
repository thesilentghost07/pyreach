"""
Comprehensive tests for backend.reachability (Member 2 – Vibhav).

Each test uses synthetic ProjectASTResult / AdvisoryMatch fixtures so
nothing is fabricated and no project code is executed.
"""

from __future__ import annotations

import pytest

from backend.schemas import (
    AdvisoryMatch,
    CallSite,
    EvidenceStep,
    Finding,
    FunctionDefRecord,
    ImportRecord,
    ParsedFile,
    ProjectASTResult,
    Verdict,
)
from backend.reachability import (
    analyze_reachability,
    build_call_graph,
    collect_uncertainty_hazards,
    find_shortest_evidence_path,
)


# ─── Shared fixtures ────────────────────────────────────────────────────


def _make_multi_hop_ast() -> ProjectASTResult:
    """Create a 3-hop call chain:

        main.<module> -> main.run_pipeline -> app.utils.parse_config -> yaml.load

    All files parse cleanly, no dynamic calls.
    """
    return ProjectASTResult(
        project_path="/project",
        entry_points=["main.<module>"],
        files=[
            ParsedFile(
                file_path="main.py",
                imports=[
                    ImportRecord(
                        module="app.utils",
                        imported_name="parse_config",
                        alias="parse_config",
                        file="main.py",
                        line=1,
                    ),
                ],
                functions=[
                    FunctionDefRecord(
                        qualname="main.run_pipeline",
                        name="run_pipeline",
                        file="main.py",
                        line=5,
                        is_entry_point=False,
                    ),
                ],
                calls=[
                    # <module> calls run_pipeline
                    CallSite(
                        caller_qualname="main.<module>",
                        raw_callee="run_pipeline",
                        resolved_callee="main.run_pipeline",
                        file="main.py",
                        line=10,
                    ),
                    # run_pipeline calls parse_config
                    CallSite(
                        caller_qualname="main.run_pipeline",
                        raw_callee="parse_config",
                        resolved_callee="app.utils.parse_config",
                        file="main.py",
                        line=6,
                    ),
                ],
            ),
            ParsedFile(
                file_path="app/utils.py",
                imports=[
                    ImportRecord(
                        module="yaml",
                        imported_name="load",
                        alias="load",
                        file="app/utils.py",
                        line=1,
                    ),
                ],
                functions=[
                    FunctionDefRecord(
                        qualname="app.utils.parse_config",
                        name="parse_config",
                        file="app/utils.py",
                        line=3,
                    ),
                ],
                calls=[
                    # parse_config calls yaml.load
                    CallSite(
                        caller_qualname="app.utils.parse_config",
                        raw_callee="yaml.load",
                        file="app/utils.py",
                        line=5,
                    ),
                ],
            ),
        ],
    )


def _pyyaml_advisory(
    vulnerable_symbols: list[str] | None = None,
    installed_version: str | None = "5.3.1",
) -> AdvisoryMatch:
    return AdvisoryMatch(
        package="pyyaml",
        installed_version=installed_version,
        advisory_id="CVE-2020-XXXXX",
        summary="Unsafe yaml.load allows arbitrary code execution",
        affected_versions="<6.0",
        vulnerable_symbols=vulnerable_symbols if vulnerable_symbols is not None else ["yaml.load"],
        symbol_source="osv",
    )


# ─── Test 1: Multi-hop REACHABLE path ───────────────────────────────────


class TestReachableMultiHop:
    """Verify a 3-hop path is found with exact EvidenceStep order."""

    def test_verdict_is_reachable(self) -> None:
        ast = _make_multi_hop_ast()
        adv = _pyyaml_advisory()
        findings = analyze_reachability(ast, [adv])

        assert len(findings) == 1
        f = findings[0]
        assert f.verdict == Verdict.REACHABLE
        assert f.confidence == "high"
        assert f.vulnerable_symbol == "yaml.load"
        assert f.package == "pyyaml"
        assert f.advisory_id == "CVE-2020-XXXXX"
        assert len(f.uncertainty_reasons) == 0

    def test_evidence_steps_order(self) -> None:
        ast = _make_multi_hop_ast()
        findings = analyze_reachability(ast, [_pyyaml_advisory()])
        evidence = findings[0].evidence

        # Expect exactly 3 hops
        assert len(evidence) == 3

        # Hop 1: main.<module> -> main.run_pipeline
        assert evidence[0].from_symbol == "main.<module>"
        assert evidence[0].to_symbol == "main.run_pipeline"
        assert evidence[0].file == "main.py"
        assert evidence[0].line == 10

        # Hop 2: main.run_pipeline -> app.utils.parse_config
        assert evidence[1].from_symbol == "main.run_pipeline"
        assert evidence[1].to_symbol == "app.utils.parse_config"
        assert evidence[1].file == "main.py"
        assert evidence[1].line == 6

        # Hop 3: app.utils.parse_config -> yaml.load
        assert evidence[2].from_symbol == "app.utils.parse_config"
        assert evidence[2].to_symbol == "yaml.load"
        assert evidence[2].file == "app/utils.py"
        assert evidence[2].line == 5

    def test_evidence_by_alias_serialization(self) -> None:
        """EvidenceStep must serialize with 'from' / 'to' keys (not from_symbol)."""
        ast = _make_multi_hop_ast()
        findings = analyze_reachability(ast, [_pyyaml_advisory()])
        step_dict = findings[0].evidence[0].model_dump(by_alias=True)

        assert "from" in step_dict
        assert "to" in step_dict
        assert step_dict["from"] == "main.<module>"
        assert step_dict["to"] == "main.run_pipeline"
        # Internal field names must NOT appear in aliased output
        assert "from_symbol" not in step_dict
        assert "to_symbol" not in step_dict


# ─── Test 2: NOT_REACHABLE (safe_load only, no hazards) ─────────────────


class TestNotReachable:
    """yaml.safe_load is used – no path to yaml.load, no hazards."""

    def test_verdict_is_not_reachable(self) -> None:
        ast = ProjectASTResult(
            project_path="/project",
            entry_points=["main.<module>"],
            files=[
                ParsedFile(
                    file_path="main.py",
                    functions=[
                        FunctionDefRecord(
                            qualname="main.load_config",
                            name="load_config",
                            file="main.py",
                            line=3,
                        ),
                    ],
                    calls=[
                        CallSite(
                            caller_qualname="main.<module>",
                            raw_callee="load_config",
                            resolved_callee="main.load_config",
                            file="main.py",
                            line=10,
                        ),
                        # Only safe_load is called – NOT yaml.load
                        CallSite(
                            caller_qualname="main.load_config",
                            raw_callee="yaml.safe_load",
                            file="main.py",
                            line=5,
                        ),
                    ],
                ),
            ],
        )
        adv = _pyyaml_advisory(installed_version="5.3.1")
        findings = analyze_reachability(ast, [adv])

        assert len(findings) == 1
        f = findings[0]
        assert f.verdict == Verdict.NOT_REACHABLE
        assert f.confidence == "medium"
        assert "yaml.load" in f.vulnerable_symbol
        assert len(f.evidence) == 0
        assert len(f.uncertainty_reasons) == 0
        assert "No static call path" in f.reason


# ─── Test 3: UNCERTAIN when vulnerable_symbols is empty ──────────────────


class TestUncertainEmptySymbols:
    """Advisory has no vulnerable_symbols → always UNCERTAIN."""

    def test_verdict_uncertain_empty_symbols(self) -> None:
        ast = _make_multi_hop_ast()
        adv = _pyyaml_advisory(vulnerable_symbols=[])
        findings = analyze_reachability(ast, [adv])

        assert len(findings) == 1
        f = findings[0]
        assert f.verdict == Verdict.UNCERTAIN
        assert f.confidence == "low"
        assert f.vulnerable_symbol is None
        assert any("does not specify" in r for r in f.uncertainty_reasons)
        assert "no vulnerable function symbols are mapped" in f.reason


# ─── Test 4: UNCERTAIN due to dynamic call hazard ────────────────────────


class TestUncertainDynamicCall:
    """No static path to yaml.load, but getattr-based dynamic call exists."""

    def test_verdict_uncertain_dynamic_hazard(self) -> None:
        ast = ProjectASTResult(
            project_path="/project",
            entry_points=["main.<module>"],
            files=[
                ParsedFile(
                    file_path="main.py",
                    functions=[
                        FunctionDefRecord(
                            qualname="main.dispatch",
                            name="dispatch",
                            file="main.py",
                            line=3,
                        ),
                    ],
                    calls=[
                        CallSite(
                            caller_qualname="main.<module>",
                            raw_callee="dispatch",
                            resolved_callee="main.dispatch",
                            file="main.py",
                            line=10,
                        ),
                        # dynamic getattr call – could invoke yaml.load at runtime
                        CallSite(
                            caller_qualname="main.dispatch",
                            raw_callee="getattr(yaml, user_fn)",
                            file="main.py",
                            line=6,
                            is_dynamic=True,
                            dynamic_reason="getattr-based dynamic invocation",
                        ),
                    ],
                ),
            ],
        )
        adv = _pyyaml_advisory()
        findings = analyze_reachability(ast, [adv])

        assert len(findings) == 1
        f = findings[0]
        assert f.verdict == Verdict.UNCERTAIN
        assert f.confidence == "low"
        assert any("Dynamic call hazard" in r for r in f.uncertainty_reasons)


# ─── Test 5: UNCERTAIN due to parse error ────────────────────────────────


class TestUncertainParseError:
    """No static path, but one file has a parse error → UNCERTAIN."""

    def test_verdict_uncertain_parse_error(self) -> None:
        ast = ProjectASTResult(
            project_path="/project",
            entry_points=["main.<module>"],
            files=[
                ParsedFile(
                    file_path="main.py",
                    calls=[
                        CallSite(
                            caller_qualname="main.<module>",
                            raw_callee="yaml.safe_load",
                            file="main.py",
                            line=3,
                        ),
                    ],
                ),
                ParsedFile(
                    file_path="broken.py",
                    parse_error="SyntaxError: invalid syntax (line 10)",
                ),
            ],
        )
        adv = _pyyaml_advisory()
        findings = analyze_reachability(ast, [adv])

        assert len(findings) == 1
        f = findings[0]
        assert f.verdict == Verdict.UNCERTAIN
        assert f.confidence == "low"
        assert any("Syntax/parse error" in r for r in f.uncertainty_reasons)
        assert any("broken.py" in r for r in f.uncertainty_reasons)


# ─── Test 6: Cycle / recursion safety ────────────────────────────────────


class TestCycleSafety:
    """func_a ↔ func_b mutual recursion must NOT hang BFS."""

    def test_bfs_terminates_with_cycle(self) -> None:
        ast = ProjectASTResult(
            project_path="/project",
            entry_points=["main.<module>"],
            files=[
                ParsedFile(
                    file_path="main.py",
                    functions=[
                        FunctionDefRecord(
                            qualname="main.func_a",
                            name="func_a",
                            file="main.py",
                            line=1,
                        ),
                        FunctionDefRecord(
                            qualname="main.func_b",
                            name="func_b",
                            file="main.py",
                            line=10,
                        ),
                    ],
                    calls=[
                        CallSite(
                            caller_qualname="main.<module>",
                            raw_callee="func_a",
                            resolved_callee="main.func_a",
                            file="main.py",
                            line=20,
                        ),
                        # func_a -> func_b
                        CallSite(
                            caller_qualname="main.func_a",
                            raw_callee="func_b",
                            resolved_callee="main.func_b",
                            file="main.py",
                            line=3,
                        ),
                        # func_b -> func_a  (cycle!)
                        CallSite(
                            caller_qualname="main.func_b",
                            raw_callee="func_a",
                            resolved_callee="main.func_a",
                            file="main.py",
                            line=12,
                        ),
                    ],
                ),
            ],
        )
        adv = _pyyaml_advisory()

        # This must terminate (not hang) and return NOT_REACHABLE
        findings = analyze_reachability(ast, [adv])

        assert len(findings) == 1
        f = findings[0]
        # No path to yaml.load and no hazards → NOT_REACHABLE
        assert f.verdict == Verdict.NOT_REACHABLE
        assert f.confidence == "medium"


# ─── Test: helper unit tests ────────────────────────────────────────────


class TestBuildCallGraph:
    def test_caller_map_contains_all_callers(self) -> None:
        ast = _make_multi_hop_ast()
        caller_map, qn_lookup, short_lookup = build_call_graph(ast)

        assert "main.<module>" in caller_map
        assert "main.run_pipeline" in caller_map
        assert "app.utils.parse_config" in caller_map

    def test_qualname_lookup(self) -> None:
        ast = _make_multi_hop_ast()
        _, qn_lookup, _ = build_call_graph(ast)

        assert "main.run_pipeline" in qn_lookup
        assert "app.utils.parse_config" in qn_lookup

    def test_short_name_lookup(self) -> None:
        ast = _make_multi_hop_ast()
        _, _, short_lookup = build_call_graph(ast)

        assert "run_pipeline" in short_lookup
        assert "parse_config" in short_lookup


class TestCollectHazards:
    def test_no_hazards_on_clean_ast(self) -> None:
        ast = _make_multi_hop_ast()
        assert collect_uncertainty_hazards(ast) == []

    def test_collects_parse_and_dynamic_hazards(self) -> None:
        ast = ProjectASTResult(
            project_path="/p",
            files=[
                ParsedFile(file_path="a.py", parse_error="bad syntax"),
                ParsedFile(
                    file_path="b.py",
                    calls=[
                        CallSite(
                            caller_qualname="b.f",
                            raw_callee="eval(x)",
                            file="b.py",
                            line=7,
                            is_dynamic=True,
                            dynamic_reason="eval call",
                        ),
                    ],
                ),
            ],
        )
        hazards = collect_uncertainty_hazards(ast)
        assert len(hazards) == 2
        assert "Syntax/parse error in a.py" in hazards[0]
        assert "Dynamic call hazard at b.py:7" in hazards[1]
