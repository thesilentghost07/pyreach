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
import shutil
import tempfile
import zipfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_index():
    """Serve the PyReach static reachability web dashboard."""
    for candidate in [
        REPO_ROOT / "frontend" / "index.html",
        Path("frontend/index.html"),
        REPO_ROOT / "html" / "main.html",
        REPO_ROOT / "index.html",
    ]:
        if candidate.is_file():
            return FileResponse(candidate)
    return HTMLResponse("<h1>PyReach Dashboard</h1><p>frontend/index.html not found</p>")


@app.get("/html/main.html", response_class=HTMLResponse, include_in_schema=False)
def get_dashboard_html():
    """Direct route for dashboard HTML."""
    return FileResponse(REPO_ROOT / "html" / "main.html")


frontend_dir = REPO_ROOT / "frontend"
if frontend_dir.is_dir():
    app.mount("/frontend", StaticFiles(directory=str(frontend_dir)), name="frontend")


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


def _generate_remediation(finding: Finding) -> tuple[str, str]:
    if finding.verdict != Verdict.REACHABLE:
        return "", ""
    pkg = (finding.package or "").lower()
    if "yaml" in pkg:
        cmd = 'pip install --upgrade "pyyaml>=5.4"'
        advice = "Upgrade to PyYAML >=5.4 or migrate to yaml.safe_load."
    else:
        cmd = f'pip install --upgrade "{finding.package}>=latest"'
        advice = f"Upgrade {finding.package} to the latest patched version."
    return advice, cmd


def _run_scan_pipeline(
    target_path: Path,
    project_label: str = "",
    use_network: bool = False,
) -> dict:
    if scan_project_ast is None:
        raise HTTPException(
            status_code=501,
            detail="Analyzer module (ast_scanner) not available yet.",
        )
    if analyze_reachability is None:
        raise HTTPException(
            status_code=501,
            detail="Analyzer module (reachability) not available yet.",
        )

    dependencies, advisories, warnings = resolve_dependencies_and_advisories(
        target_path, use_network=use_network
    )
    ast_result = scan_project_ast(target_path)
    for pf in ast_result.files:
        if pf.parse_error:
            msg = f"AST parse error in {pf.file_path}: {pf.parse_error}"
            if msg not in warnings:
                warnings.append(msg)

    findings = analyze_reachability(ast_result, advisories)

    reachable_count = sum(1 for f in findings if f.verdict == Verdict.REACHABLE)
    not_reachable_count = sum(1 for f in findings if f.verdict == Verdict.NOT_REACHABLE)
    uncertain_count = sum(1 for f in findings if f.verdict == Verdict.UNCERTAIN)

    findings_json = []
    for f in findings:
        remediation, remediation_cmd = _generate_remediation(f)
        evidence_list = [
            {
                "from": step.from_symbol,
                "to": step.to_symbol,
                "file": step.file,
                "line": step.line,
            }
            for step in f.evidence
        ]
        call_trace = [f"{step.from_symbol} -> {step.to_symbol}" for step in f.evidence]

        findings_json.append({
            "package": f.package,
            "version": f.installed_version,
            "installed_version": f.installed_version,
            "advisory_id": f.advisory_id,
            "confidence": f.confidence,
            "summary": f.summary,
            "verdict": f.verdict.value,
            "vulnerable_symbol": f.vulnerable_symbol,
            "target_sink": f.vulnerable_symbol,
            "evidence": evidence_list,
            "call_trace": call_trace,
            "uncertainty_reasons": f.uncertainty_reasons,
            "reason": f.reason,
            "remediation": remediation,
            "remediation_cmd": remediation_cmd,
        })

    return {
        "status": "success",
        "project": project_label or str(target_path.name),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "analysis_scope": (
            "Static AST intraprocedural and cross-file call-graph analysis. "
            "Does not execute code or resolve runtime reflection."
        ),
        "summary": {
            "total_dependencies": len(dependencies),
            "total_deps": len(dependencies),
            "total_advisories": len(advisories),
            "reachable_count": reachable_count,
            "reachable": reachable_count,
            "not_reachable_count": not_reachable_count,
            "not_reachable": not_reachable_count,
            "uncertain_count": uncertain_count,
            "uncertain": uncertain_count,
        },
        "dependencies": [d.model_dump(mode="json") for d in dependencies],
        "findings": findings_json,
        "warnings": warnings,
    }


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
        report_dict = _run_scan_pipeline(
            target_path,
            project_label=request.project_path,
            use_network=request.use_network,
        )
        return JSONResponse(content=report_dict)

    except HTTPException:
        raise  # Let 400/501 pass through
    except Exception:
        # Catch-all: never leak stack traces to the client
        raise HTTPException(
            status_code=500,
            detail="Internal server error during project scan.",
        )


@app.post("/api/upload")
async def handle_zip_upload(
    file: UploadFile | None = File(None),
    files: list[UploadFile] = File(default_factory=list),
):
    """Accept .zip archive or uploaded folder, extract safely, and run static analysis."""
    upload_file = file
    if upload_file is None and files:
        if len(files) == 1 and files[0].filename and files[0].filename.endswith(".zip"):
            upload_file = files[0]

    if upload_file is not None:
        if not upload_file.filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="Only .zip files are supported.")

        temp_dir = Path(tempfile.mkdtemp(prefix="pyreach_upload_"))
        try:
            zip_path = temp_dir / "upload.zip"
            content = await upload_file.read()
            zip_path.write_bytes(content)

            extract_path = temp_dir / "extracted"
            extract_path.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                for member in zip_ref.namelist():
                    member_path = (extract_path / member).resolve()
                    if not member_path.is_relative_to(extract_path.resolve()):
                        raise HTTPException(
                            status_code=400, detail="Zip file contains unsafe path traversal."
                        )
                zip_ref.extractall(extract_path)

            target_dir = extract_path
            while True:
                entries = [
                    p for p in target_dir.iterdir()
                    if not p.name.startswith(".") and p.name != "__MACOSX"
                ]
                if len(entries) == 1 and entries[0].is_dir():
                    target_dir = entries[0]
                else:
                    break

            req_file = target_dir / "requirements.txt"
            if not req_file.exists():
                req_candidates = [
                    c for c in target_dir.rglob("requirements.txt")
                    if ".venv" not in c.parts and "venv" not in c.parts and "__pycache__" not in c.parts
                ]
                req_file = req_candidates[0] if req_candidates else None
                if req_file and not (target_dir / "requirements.txt").exists():
                    shutil.copy2(req_file, target_dir / "requirements.txt")

            if not req_file or not req_file.exists():
                raise HTTPException(
                    status_code=400, detail="No requirements.txt found in archive."
                )

            result = _run_scan_pipeline(
                target_dir,
                project_label=upload_file.filename or "Uploaded Archive",
                use_network=False,
            )
            return JSONResponse(content=result)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    elif files:
        temp_dir = Path(tempfile.mkdtemp(prefix="pyreach_folder_upload_"))
        try:
            extract_path = temp_dir / "extracted"
            extract_path.mkdir(parents=True, exist_ok=True)
            for f in files:
                rel_path = f.filename
                dest = extract_path / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(await f.read())

            target_dir = extract_path
            while True:
                entries = [
                    p for p in target_dir.iterdir()
                    if not p.name.startswith(".") and p.name != "__MACOSX"
                ]
                if len(entries) == 1 and entries[0].is_dir():
                    target_dir = entries[0]
                else:
                    break

            req_file = target_dir / "requirements.txt"
            if not req_file.exists():
                req_candidates = [
                    c for c in target_dir.rglob("requirements.txt")
                    if ".venv" not in c.parts and "venv" not in c.parts and "__pycache__" not in c.parts
                ]
                req_file = req_candidates[0] if req_candidates else None
                if req_file and not (target_dir / "requirements.txt").exists():
                    shutil.copy2(req_file, target_dir / "requirements.txt")

            if not req_file or not req_file.exists():
                raise HTTPException(
                    status_code=400, detail="No requirements.txt found in archive."
                )

            return _run_scan_pipeline(
                target_dir,
                project_label="Uploaded Folder",
                use_network=False,
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    else:
        raise HTTPException(status_code=400, detail="No file or folder uploaded.")


# ---------------------------------------------------------------------------
# CLI entrypoint for local development
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
