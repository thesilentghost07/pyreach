"""
main.py — FastAPI application (Member 3 / Nischay)

Exposes the scan pipeline as a REST API:
  GET  /api/health   -> {"status": "ok"}
  GET  /api/fixtures  -> list of scannable fixture/example directories
  POST /api/scan      -> full ScanReport JSON

The scan pipeline:
  1. resolve_dependencies_and_advisories (this module, deps_advisory.py)
  2. scan_project_ast (Member 1, ast_scanner.py)
  3. analyze_reachability (Member 2, reachability.py)

Member 1 and Member 2 modules are imported with safe fallback so this
file and its tests work even before those branches are merged.

SAFETY: Never executes scanned project code. All analysis is static.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.ast_scanner import scan_project_ast
from backend.deps_advisory import resolve_dependencies_and_advisories
from backend.reachability import analyze_reachability
from backend.schemas import (
    ScanReport,
    ScanSummary,
    Verdict,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Python Vulnerability Reachability Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Repository root = parent of the backend/ directory
REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    project_path: str
    use_network: bool = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health_check():
    """Simple liveness probe."""
    return {"status": "ok"}


@app.get("/api/fixtures")
def list_fixtures():
    """Discover scannable fixture and example directories.

    Looks inside tests/fixtures/ and examples/ for subdirectories
    that contain at least one .py file or a requirements.txt.
    Returns sorted relative POSIX paths from REPO_ROOT.
    """
    results: list[str] = []

    search_dirs = [
        REPO_ROOT / "tests" / "fixtures",
        REPO_ROOT / "examples",
    ]

    for parent in search_dirs:
        if not parent.is_dir():
            continue
        for child in sorted(parent.iterdir()):
            if not child.is_dir():
                continue
            # Check if child contains a .py file or requirements.txt
            has_py = any(child.glob("*.py"))
            has_req = (child / "requirements.txt").is_file()
            if has_py or has_req:
                # Convert to relative POSIX path from REPO_ROOT
                rel = child.relative_to(REPO_ROOT).as_posix()
                results.append(rel)

    return sorted(set(results))


@app.post("/api/scan")
def scan_project(request: ScanRequest):
    """Run the full scan pipeline and return a ScanReport.

    Pipeline:
      1. Parse deps + match advisories  (deps_advisory.py)
      2. Parse project AST              (ast_scanner.py — Member 1)
      3. Analyze reachability            (reachability.py — Member 2)
      4. Assemble ScanReport
    """
    # --- Validate project_path ---
    if not request.project_path or not request.project_path.strip():
        raise HTTPException(status_code=400, detail="project_path must not be empty.")

    target_path = (REPO_ROOT / request.project_path).resolve()

    # Path-traversal protection: must stay inside REPO_ROOT
    try:
        if not target_path.is_relative_to(REPO_ROOT):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Path '{request.project_path}' resolves outside the "
                    f"repository root. Path traversal is not allowed."
                ),
            )
    except TypeError:
        # is_relative_to not available on very old Python (< 3.9)
        if not str(target_path).startswith(str(REPO_ROOT)):
            raise HTTPException(
                status_code=400,
                detail="Path resolves outside repository root.",
            )

    if not target_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Path '{request.project_path}' does not exist.",
        )
    if not target_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Path '{request.project_path}' is not a directory.",
        )

    try:
        # --- Step 1: Deps + Advisories ---
        dependencies, advisories, warnings = resolve_dependencies_and_advisories(
            target_path, use_network=request.use_network
        )

        # --- Step 2: AST scanning (Member 1) ---
        if scan_project_ast is None:
            raise HTTPException(
                status_code=501,
                detail="Analyzer module (ast_scanner) not available yet.",
            )
        ast_result = scan_project_ast(target_path)

        # Surface any parse errors as warnings
        for pf in ast_result.files:
            if pf.parse_error:
                msg = f"AST parse error in {pf.file_path}: {pf.parse_error}"
                if msg not in warnings:
                    warnings.append(msg)

        # --- Step 3: Reachability analysis (Member 2) ---
        if analyze_reachability is None:
            raise HTTPException(
                status_code=501,
                detail="Analyzer module (reachability) not available yet.",
            )
        findings = analyze_reachability(ast_result, advisories)

        # --- Step 4: Assemble report ---
        summary = ScanSummary(
            total_dependencies=len(dependencies),
            total_advisories=len(advisories),
            reachable_count=sum(
                1 for f in findings if f.verdict == Verdict.REACHABLE
            ),
            not_reachable_count=sum(
                1 for f in findings if f.verdict == Verdict.NOT_REACHABLE
            ),
            uncertain_count=sum(
                1 for f in findings if f.verdict == Verdict.UNCERTAIN
            ),
        )

        report = ScanReport(
            project=request.project_path,
            scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            summary=summary,
            dependencies=dependencies,
            findings=findings,
            warnings=warnings,
        )

        # Serialize with by_alias=True so EvidenceStep uses "from"/"to" keys
        return JSONResponse(
            content=report.model_dump(mode="json", by_alias=True)
        )

    except HTTPException:
        raise  # Let 400/501 pass through
    except Exception:
        # Catch-all: never leak stack traces to the client
        raise HTTPException(
            status_code=500,
            detail="Internal server error during project scan.",
        )


# ---------------------------------------------------------------------------
# CLI entrypoint for local development
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
