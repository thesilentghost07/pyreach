"""
backend/cli.py
~~~~~~~~~~~~~~
Command-line interface and GitHub Markdown reporting tool for PyReach.

Usage:
    python -m backend.cli [targets...] [options]

Features:
    - Scans one or more Python projects for vulnerable dependency reachability.
    - Defaults to tests/fixtures/{reachable,not_reachable,uncertain}_app if present, else ["."].
    - Formats output as GitHub Markdown (with summary table, detailed findings,
      and remediation callout) or raw JSON.
    - Supports --fail-on-reachable flag to exit with status 1 on confirmed reachability.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from backend.ast_scanner import scan_project_ast
from backend.deps_advisory import resolve_dependencies_and_advisories
from backend.reachability import analyze_reachability
from backend.schemas import (
    Finding,
    ScanReport,
    ScanSummary,
    Verdict,
)

DEFAULT_FIXTURES: List[str] = [
    "tests/fixtures/reachable_app",
    "tests/fixtures/not_reachable_app",
    "tests/fixtures/uncertain_app",
]


def resolve_targets(cli_targets: List[str]) -> List[str]:
    """Resolve target directories from CLI args, falling back to fixtures or current dir."""
    if cli_targets:
        return cli_targets
    if all(Path(p).is_dir() for p in DEFAULT_FIXTURES):
        return list(DEFAULT_FIXTURES)
    return ["."]


def scan_directory(target_path: Path, use_network: bool = False) -> ScanReport:
    """Run full static analysis pipeline on a project directory and return a ScanReport."""
    resolved_path = target_path.resolve()
    if not resolved_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_path}")
    if not resolved_path.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_path}")

    # Step 1: Resolve dependencies and vulnerability advisories
    deps, advisories, warnings = resolve_dependencies_and_advisories(
        resolved_path, use_network=use_network
    )

    # Step 2: Parse project AST
    ast_result = scan_project_ast(resolved_path)
    for pf in ast_result.files:
        if pf.parse_error:
            msg = f"AST parse error in {pf.file_path}: {pf.parse_error}"
            if msg not in warnings:
                warnings.append(msg)

    # Step 3: Run call-graph BFS reachability analysis
    findings = analyze_reachability(ast_result, advisories)

    # Step 4: Assemble ScanSummary and ScanReport
    summary = ScanSummary(
        total_dependencies=len(deps),
        total_advisories=len(advisories),
        reachable_count=sum(1 for f in findings if f.verdict == Verdict.REACHABLE),
        not_reachable_count=sum(
            1 for f in findings if f.verdict == Verdict.NOT_REACHABLE
        ),
        uncertain_count=sum(
            1 for f in findings if f.verdict == Verdict.UNCERTAIN
        ),
    )

    return ScanReport(
        project=str(target_path),
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        summary=summary,
        dependencies=deps,
        findings=findings,
        warnings=warnings,
    )


def _clean_table_cell(text: str) -> str:
    """Escape pipe characters and line breaks for safe markdown table embedding."""
    return text.replace("|", "\\|").replace("\n", "<br>")


def _format_evidence_cell(finding: Finding) -> str:
    """Format the Impact & Evidence Path column cell content."""
    if finding.verdict == Verdict.REACHABLE:
        parts: List[str] = []
        if finding.vulnerable_symbol:
            parts.append(f"**Target Sink:** `{finding.vulnerable_symbol}`")
        if finding.evidence:
            chain_nodes = []
            for s in finding.evidence:
                if not chain_nodes:
                    chain_nodes.append(f"`{s.from_symbol}`")
                chain_nodes.append(f"`{s.to_symbol}`")
            chain = " → ".join(chain_nodes)
            locs = ", ".join(f"`{s.file}:{s.line}`" for s in finding.evidence)
            parts.append(f"**Call Chain:** {chain} ({locs})")
        else:
            parts.append(f"**Reason:** {finding.reason}")
        return "<br>".join(parts)

    elif finding.verdict == Verdict.NOT_REACHABLE:
        sym = f"`{finding.vulnerable_symbol}`" if finding.vulnerable_symbol else "vulnerable sink"
        return f"No static call path to {sym} detected from application entry points (safe alternatives used)."

    elif finding.verdict == Verdict.UNCERTAIN:
        if finding.uncertainty_reasons:
            hazards = "; ".join(finding.uncertainty_reasons)
            return _clean_table_cell(f"**Uncertainty Hazard:** {hazards}")
        return _clean_table_cell(f"**Uncertain:** {finding.reason}")

    return _clean_table_cell(finding.reason)


def format_markdown_report(reports: List[ScanReport]) -> str:
    """Format one or more ScanReports into a GitHub-compatible Markdown security report."""
    total_deps = sum(r.summary.total_dependencies for r in reports)
    total_advisories = sum(r.summary.total_advisories for r in reports)
    total_reachable = sum(r.summary.reachable_count for r in reports)
    total_not_reachable = sum(r.summary.not_reachable_count for r in reports)
    total_uncertain = sum(r.summary.uncertain_count for r in reports)

    lines: List[str] = [
        "## 🛡️ PyReach Vulnerability Reachability Report",
        "",
        "### 📊 Scan Summary",
        f"- **Analyzed Dependencies:** {total_deps}",
        f"- **Advisories:** {total_advisories}",
        f"- **🔴 Reachable:** {total_reachable}",
        f"- **🟢 Not Reachable:** {total_not_reachable}",
        f"- **🟡 Uncertain:** {total_uncertain}",
        "",
        "| Analyzed Dependencies | Advisories | 🔴 Reachable | 🟢 Not Reachable | 🟡 Uncertain |",
        "| :---: | :---: | :---: | :---: | :---: |",
        f"| {total_deps} | {total_advisories} | {total_reachable} | {total_not_reachable} | {total_uncertain} |",
        "",
        "### 🔍 Detailed Findings",
        "",
        "| Package | CVE / Advisory | Verdict | Impact & Evidence Path |",
        "| :--- | :--- | :--- | :--- |",
    ]

    all_findings: List[Tuple[str, Finding]] = []
    for r in reports:
        for f in r.findings:
            all_findings.append((r.project, f))

    if not all_findings:
        lines.append(
            "| _None_ | _None_ | 🟢 NOT_REACHABLE | No vulnerability advisories matched for scanned dependencies. |"
        )
    else:
        for project_name, finding in all_findings:
            pkg_str = f"`{finding.package}`"
            if finding.installed_version:
                pkg_str += f" ({finding.installed_version})"
            if len(reports) > 1:
                pkg_str += f"<br><sub>📁 `{project_name}`</sub>"

            cve_str = f"`{finding.advisory_id}`"

            if finding.verdict == Verdict.REACHABLE:
                verdict_str = "🔴 REACHABLE"
            elif finding.verdict == Verdict.NOT_REACHABLE:
                verdict_str = "🟢 NOT_REACHABLE"
            else:
                verdict_str = "🟡 UNCERTAIN"

            evidence_str = _format_evidence_cell(finding)
            lines.append(f"| {pkg_str} | {cve_str} | {verdict_str} | {evidence_str} |")

    # Remediation callout if any reachable finding exists
    reachable_findings = [f for _, f in all_findings if f.verdict == Verdict.REACHABLE]
    if reachable_findings:
        lines.extend([
            "",
            "### 🛠️ Remediation & Safe Alternatives",
            "",
            "> [!WARNING]",
            "> **Reachable Vulnerabilities Detected**",
            ">",
            "> Static AST analysis confirmed direct call paths to vulnerable sinks:",
        ])
        for f in reachable_findings:
            pkg_name = f.package.lower()
            if "yaml" in pkg_name:
                lines.extend([
                    f"> - **{f.package}** (`{f.vulnerable_symbol}`):",
                    ">   - **Safe Alternative:** Replace calls to `yaml.load(...)` with `yaml.safe_load(...)` to prevent arbitrary code execution during untrusted deserialization.",
                    ">   - **Recommended Action:** Upgrade `pyyaml` to `>=5.4` or restrict loader to safe loaders.",
                ])
            else:
                lines.extend([
                    f"> - **{f.package}** (`{f.vulnerable_symbol}`):",
                    f">   - **Safe Alternative:** Avoid invoking vulnerable function `{f.vulnerable_symbol}` or sanitize input before dispatch.",
                    f">   - **Recommended Action:** Upgrade `{f.package}` to a patched release.",
                ])

    lines.extend([
        "",
        "---",
        "_Generated by **PyReach** Static Reachability Guard. Scope: Intraprocedural and cross-file AST call graph analysis._",
    ])

    return "\n".join(lines)


def format_json_report(reports: List[ScanReport]) -> str:
    """Format one or more ScanReports into JSON."""
    if len(reports) == 1:
        data = reports[0].model_dump(mode="json", by_alias=True)
    else:
        data = [r.model_dump(mode="json", by_alias=True) for r in reports]
    return json.dumps(data, indent=2)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for PyReach CLI."""
    parser = argparse.ArgumentParser(
        prog="pyreach",
        description="PyReach: Python Vulnerability Reachability Analyzer & CI Guard",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target project directory path(s) to scan (defaults to fixtures or current dir)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format: 'markdown' (default) or 'json'",
    )
    parser.add_argument(
        "--offline",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run offline using local symbol_map.json (default: True)",
    )
    parser.add_argument(
        "--online",
        dest="offline",
        action="store_false",
        help="Run online querying the OSV API",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path to write output file (defaults to stdout)",
    )
    parser.add_argument(
        "--fail-on-reachable",
        action="store_true",
        default=False,
        help="Exit with code 1 if a REACHABLE vulnerability is found (default: exit 0)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint. Returns exit code 0 or 1."""
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = resolve_targets(args.targets)
    use_network = not args.offline

    reports: List[ScanReport] = []
    for target in targets:
        target_path = Path(target)
        try:
            report = scan_directory(target_path, use_network=use_network)
            reports.append(report)
        except Exception as exc:
            print(f"Error scanning {target}: {exc}", file=sys.stderr)
            return 1

    if args.format == "json":
        output_text = format_json_report(reports)
    else:
        output_text = format_markdown_report(reports)

    if args.output:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(output_text, encoding="utf-8")
    else:
        print(output_text)

    has_reachable = any(
        f.verdict == Verdict.REACHABLE
        for r in reports
        for f in r.findings
    )

    if args.fail_on_reachable and has_reachable:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
