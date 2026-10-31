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
from fastapi.staticfiles import StaticFiles
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


class UploadFileItem(BaseModel):
    path: str
    content: str


class UploadScanRequest(BaseModel):
    files: list[UploadFileItem]
    project_name: str = "uploaded_project"
    use_network: bool = True


# ---------------------------------------------------------------------------
# Core Scan Pipeline Helper
# ---------------------------------------------------------------------------

def _run_scan_pipeline(
    target_path: Path, project_label: str, use_network: bool
) -> dict:
    """Execute the reachability scan pipeline on a validated target directory."""
    # Step 1: Deps + Advisories
    dependencies, advisories, warnings = resolve_dependencies_and_advisories(
        target_path, use_network=use_network
    )

    # Step 2: AST scanning (Member 1)
    if scan_project_ast is None:
        raise HTTPException(
            status_code=501,
            detail="Analyzer module (ast_scanner) not available yet.",
        )
    ast_result = scan_project_ast(target_path)

    # Surface parse errors as warnings
    for pf in ast_result.files:
        if pf.parse_error:
            msg = f"AST parse error in {pf.file_path}: {pf.parse_error}"
            if msg not in warnings:
                warnings.append(msg)

    # Step 3: Reachability analysis (Member 2)
    if analyze_reachability is None:
        raise HTTPException(
            status_code=501,
            detail="Analyzer module (reachability) not available yet.",
        )
    findings = analyze_reachability(ast_result, advisories)

    # Step 4: Assemble report
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
        project=project_label,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        summary=summary,
        dependencies=dependencies,
        findings=findings,
        warnings=warnings,
    )

    return report.model_dump(mode="json", by_alias=True)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health_check():
    """Simple liveness probe."""
    return {"status": "ok"}


@app.get("/api/fixtures")
def list_fixtures():
    """Discover scannable fixture and example directories."""
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
            has_py = any(child.glob("*.py"))
            has_req = (child / "requirements.txt").is_file()
            if has_py or has_req:
                rel = child.relative_to(REPO_ROOT).as_posix()
                results.append(rel)

    return sorted(set(results))


@app.post("/api/scan")
def scan_project(request: ScanRequest):
    """Run the full scan pipeline and return a ScanReport."""
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
        data = _run_scan_pipeline(
            target_path, request.project_path, request.use_network
        )
        return JSONResponse(content=data)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Internal server error during project scan.",
        )


@app.post("/api/scan/upload")
def scan_uploaded_project(request: UploadScanRequest):
    """Scan a project uploaded as in-memory files from the browser.

    Writes the files into a temporary sandbox inside REPO_ROOT / '_tmp_uploads',
    executes the deterministic static analysis pipeline, cleans up the sandbox,
    and returns the ScanReport.
    """
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided in upload.")

    import shutil
    import uuid

    upload_id = f"upload_{uuid.uuid4().hex[:8]}"
    upload_dir = REPO_ROOT / "_tmp_uploads" / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    try:
        for file_item in request.files:
            clean_rel = Path(file_item.path).as_posix().lstrip("/")
            if ".." in clean_rel:
                continue
            dest_file = upload_dir / clean_rel
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_text(file_item.content, encoding="utf-8", errors="replace")

        rel_label = f"uploaded/{request.project_name}"
        data = _run_scan_pipeline(upload_dir, rel_label, request.use_network)
        return JSONResponse(content=data)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Internal server error during uploaded project scan.",
        )
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Mount static frontend
# ---------------------------------------------------------------------------

_frontend_dir = REPO_ROOT / "frontend"
if _frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")


# ---------------------------------------------------------------------------
# CLI entrypoint for local development
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
