"""
Reachability analysis engine (Member 2 – Vibhav).

Builds a directed call graph from a ProjectASTResult, then runs BFS from
application entry points to determine whether known vulnerable symbols
are statically reachable.  Produces a deterministic list[Finding] with
conservative verdicts: REACHABLE, NOT_REACHABLE, or UNCERTAIN.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from backend.schemas import (
    AdvisoryMatch,
    CallSite,
    EvidenceStep,
    Finding,
    FunctionDefRecord,
    ParsedFile,
    ProjectASTResult,
    Verdict,
)

# ── helpers ──────────────────────────────────────────────────────────────


def build_call_graph(
    ast_result: ProjectASTResult,
) -> Tuple[
    Dict[str, List[CallSite]],
    Dict[str, FunctionDefRecord],
    Dict[str, FunctionDefRecord],
]:
    """Return (caller_qualname → [CallSite], qualname → FuncDef, short_name → FuncDef)."""
    caller_map: Dict[str, List[CallSite]] = {}
    qualname_lookup: Dict[str, FunctionDefRecord] = {}
    short_name_lookup: Dict[str, FunctionDefRecord] = {}

    for pf in ast_result.files:
        for func in pf.functions:
            qualname_lookup[func.qualname] = func
            # Only store the first match per short name to keep it deterministic
            if func.name not in short_name_lookup:
                short_name_lookup[func.name] = func

        for call in pf.calls:
            caller_map.setdefault(call.caller_qualname, []).append(call)

    return caller_map, qualname_lookup, short_name_lookup


def collect_uncertainty_hazards(ast_result: ProjectASTResult) -> List[str]:
    """Gather global uncertainty reasons from parse errors and dynamic calls."""
    hazards: List[str] = []

    for pf in ast_result.files:
        if pf.parse_error is not None:
            hazards.append(
                f"Syntax/parse error in {pf.file_path}: {pf.parse_error}"
            )
        for call in pf.calls:
            if call.is_dynamic:
                reason = call.dynamic_reason or "dynamic invocation"
                hazards.append(
                    f"Dynamic call hazard at {call.file}:{call.line} "
                    f"({call.raw_callee}): {reason}"
                )

    return hazards


def _symbol_matches(callee: str, vuln_sym: str) -> bool:
    """Check whether *callee* matches *vuln_sym* exactly or by suffix/prefix boundary.

    Examples that match:
        callee="yaml.load"        vuln_sym="yaml.load"         → exact
        callee="urllib3.poolmanager.PoolManager"
                                   vuln_sym="urllib3.PoolManager" → suffix
        callee="yaml.load"        vuln_sym="pyyaml.yaml.load"  → suffix
    """
    if callee == vuln_sym:
        return True
    # suffix: callee ends with ".vuln_sym" or vuln_sym ends with ".callee"
    if callee.endswith(f".{vuln_sym}") or vuln_sym.endswith(f".{callee}"):
        return True
    return False


def _resolve_callee_to_qualname(
    call: CallSite,
    qualname_lookup: Dict[str, FunctionDefRecord],
    short_name_lookup: Dict[str, FunctionDefRecord],
) -> Optional[str]:
    """Try to map a CallSite's callee to a known project function qualname."""
    callee = call.resolved_callee or call.raw_callee

    if callee in qualname_lookup:
        return callee

    if callee in short_name_lookup:
        return short_name_lookup[callee].qualname

    # Try matching the tail segment (e.g. "utils.parse_config" → "app.utils.parse_config")
    for qn in qualname_lookup:
        if qn.endswith(f".{callee}"):
            return qn

    return None


def find_shortest_evidence_path(
    entry_points: List[str],
    caller_map: Dict[str, List[CallSite]],
    qualname_lookup: Dict[str, FunctionDefRecord],
    short_name_lookup: Dict[str, FunctionDefRecord],
    vulnerable_symbols: List[str],
) -> Optional[Tuple[str, str, List[EvidenceStep]]]:
    """BFS from entry points to any vulnerable symbol.

    Returns ``(entry_point, matched_vuln_sym, evidence_steps)`` or ``None``.
    """
    # Queue items: (current_qualname, path_so_far)
    # path_so_far is a list of (from_sym, to_sym, file, line) tuples.
    queue: deque[Tuple[str, str, List[Tuple[str, str, str, int]]]] = deque()
    visited: Set[str] = set()

    for ep in entry_points:
        queue.append((ep, ep, []))
        visited.add(ep)

    while queue:
        current, origin_ep, path = queue.popleft()

        for call in caller_map.get(current, []):
            callee = call.resolved_callee or call.raw_callee
            hop = (current, callee, call.file, call.line)

            # Check if this callee IS a vulnerable symbol
            for vuln_sym in vulnerable_symbols:
                if _symbol_matches(callee, vuln_sym):
                    evidence = [
                        EvidenceStep(
                            from_symbol=f, to_symbol=t, file=fi, line=li
                        )
                        for f, t, fi, li in [*path, hop]
                    ]
                    return (origin_ep, vuln_sym, evidence)

            # Try to resolve callee to a project-internal function and continue BFS
            resolved_qn = _resolve_callee_to_qualname(
                call, qualname_lookup, short_name_lookup
            )
            next_node = resolved_qn if resolved_qn is not None else callee

            if next_node not in visited:
                visited.add(next_node)
                queue.append((next_node, origin_ep, [*path, hop]))

    return None


# ── main entry point ─────────────────────────────────────────────────────


def analyze_reachability(
    ast_result: ProjectASTResult,
    advisories: List[AdvisoryMatch],
) -> List[Finding]:
    """Produce one Finding per advisory with a deterministic verdict."""
    caller_map, qualname_lookup, short_name_lookup = build_call_graph(ast_result)
    global_hazards = collect_uncertainty_hazards(ast_result)

    # ── Resolve entry points ──
    entry_points: List[str] = list(ast_result.entry_points)
    for pf in ast_result.files:
        for func in pf.functions:
            if func.is_entry_point and func.qualname not in entry_points:
                entry_points.append(func.qualname)

    # Fallback: if nothing is explicitly marked, use <module> callers and
    # top-level functions so we don't silently miss reachability.
    if not entry_points:
        for caller_qn in caller_map:
            if caller_qn.endswith(".<module>"):
                entry_points.append(caller_qn)
        for pf in ast_result.files:
            for func in pf.functions:
                # Top-level = no nested dots beyond "module.name"
                if func.qualname.count(".") <= 1:
                    if func.qualname not in entry_points:
                        entry_points.append(func.qualname)

    findings: List[Finding] = []

    for adv in advisories:
        # ── Case A: no vulnerable symbols specified ──
        if not adv.vulnerable_symbols:
            findings.append(
                Finding(
                    package=adv.package,
                    installed_version=adv.installed_version,
                    advisory_id=adv.advisory_id,
                    confidence="low",
                    summary=adv.summary,
                    verdict=Verdict.UNCERTAIN,
                    vulnerable_symbol=None,
                    evidence=[],
                    uncertainty_reasons=[
                        "Advisory does not specify machine-readable vulnerable "
                        "function symbols; cannot safely rule out reachability.",
                        *global_hazards,
                    ],
                    reason=(
                        "Advisory matched package version, but no vulnerable "
                        "function symbols are mapped to verify code-level "
                        "reachability."
                    ),
                )
            )
            continue

        # ── Case B: vulnerable symbols are known – run BFS ──
        result = find_shortest_evidence_path(
            entry_points,
            caller_map,
            qualname_lookup,
            short_name_lookup,
            adv.vulnerable_symbols,
        )

        if result is not None:
            origin_ep, matched_sym, evidence = result
            findings.append(
                Finding(
                    package=adv.package,
                    installed_version=adv.installed_version,
                    advisory_id=adv.advisory_id,
                    confidence="high",
                    summary=adv.summary,
                    verdict=Verdict.REACHABLE,
                    vulnerable_symbol=matched_sym,
                    evidence=evidence,
                    uncertainty_reasons=[],
                    reason=(
                        f"A static call path from entry point '{origin_ep}' "
                        f"to vulnerable symbol '{matched_sym}' was confirmed."
                    ),
                )
            )
        else:
            # Collect all applicable hazards
            hazards: List[str] = list(global_hazards)
            if adv.installed_version is None:
                hazards.append(
                    "Installed version is unknown/unpinned; cannot confirm "
                    "the exact vulnerable range applies."
                )

            if hazards:
                findings.append(
                    Finding(
                        package=adv.package,
                        installed_version=adv.installed_version,
                        advisory_id=adv.advisory_id,
                        confidence="low",
                        summary=adv.summary,
                        verdict=Verdict.UNCERTAIN,
                        vulnerable_symbol=adv.vulnerable_symbols[0],
                        evidence=[],
                        uncertainty_reasons=hazards,
                        reason=(
                            "No static path found, but cannot guarantee "
                            "non-reachability due to dynamic constructs, "
                            "parse errors, or unpinned version constraints."
                        ),
                    )
                )
            else:
                joined = ", ".join(adv.vulnerable_symbols)
                findings.append(
                    Finding(
                        package=adv.package,
                        installed_version=adv.installed_version,
                        advisory_id=adv.advisory_id,
                        confidence="medium",
                        summary=adv.summary,
                        verdict=Verdict.NOT_REACHABLE,
                        vulnerable_symbol=joined,
                        evidence=[],
                        uncertainty_reasons=[],
                        reason=(
                            f"No static call path found from application "
                            f"entry points to {joined} within analyzed "
                            f"project scope (no dynamic execution hazards "
                            f"detected)."
                        ),
                    )
                )

    return findings
