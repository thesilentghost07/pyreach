"""Shared Pydantic v2 schemas for the Vulnerability Reachability Analyzer."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT_REACHABLE"
    UNCERTAIN = "UNCERTAIN"


class Dependency(BaseModel):
    name: str
    version: Optional[str] = None
    is_pinned: bool = False
    source_file: str
    line: int


class AdvisoryMatch(BaseModel):
    package: str
    installed_version: Optional[str] = None
    advisory_id: str
    summary: str
    affected_versions: str = "unknown"
    vulnerable_symbols: List[str] = Field(default_factory=list)
    symbol_source: str = "none"


class ImportRecord(BaseModel):
    module: str
    imported_name: Optional[str] = None
    alias: str
    file: str
    line: int


class CallSite(BaseModel):
    caller_qualname: str
    raw_callee: str
    resolved_callee: Optional[str] = None
    file: str
    line: int
    is_dynamic: bool = False
    dynamic_reason: Optional[str] = None


class FunctionDefRecord(BaseModel):
    qualname: str
    name: str
    file: str
    line: int
    is_entry_point: bool = False


class ParsedFile(BaseModel):
    file_path: str
    parse_error: Optional[str] = None
    imports: List[ImportRecord] = Field(default_factory=list)
    functions: List[FunctionDefRecord] = Field(default_factory=list)
    calls: List[CallSite] = Field(default_factory=list)


class ProjectASTResult(BaseModel):
    project_path: str
    files: List[ParsedFile] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)


class EvidenceStep(BaseModel):
    from_symbol: str = Field(alias="from")
    to_symbol: str = Field(alias="to")
    file: str
    line: int

    model_config = {"populate_by_name": True}


class Finding(BaseModel):
    package: str
    installed_version: Optional[str] = None
    advisory_id: str
    confidence: str
    summary: str
    verdict: Verdict
    vulnerable_symbol: Optional[str] = None
    evidence: List[EvidenceStep] = Field(default_factory=list)
    uncertainty_reasons: List[str] = Field(default_factory=list)
    reason: str


class ScanSummary(BaseModel):
    total_dependencies: int
    total_advisories: int
    reachable_count: int
    not_reachable_count: int
    uncertain_count: int


class ScanReport(BaseModel):
    project: str
    scanned_at: str
    analysis_scope: str = (
        "Static AST intraprocedural and cross-file call-graph analysis."
        " Does not execute code or resolve runtime reflection."
    )
    summary: ScanSummary
    dependencies: List[Dependency]
    findings: List[Finding]
    warnings: List[str] = Field(default_factory=list)
