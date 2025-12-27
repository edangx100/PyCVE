from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RequirementEntry:
    name: str
    spec: str
    line_no: int
    raw: str


@dataclass
class DirectiveEntry:
    line_no: int
    raw: str


@dataclass
class RequirementsParseResult:
    editable: list[RequirementEntry] = field(default_factory=list)
    directives: list[DirectiveEntry] = field(default_factory=list)
    unknown: list[DirectiveEntry] = field(default_factory=list)
    skip_reason: Optional[str] = None


@dataclass
class WorklistItem:
    name: str
    spec: str
    current_version: str
    vuln_ids: list[str]
    fix_versions: list[str]
    is_editable: bool
    skip_reason: Optional[str] = None


@dataclass
class RunContext:
    run_id: str
    run_started_at: str
    repo_url: str
    repo_dir: str
    workspace_root: str
    workspace_dir: str
    artifacts_dir: str


@dataclass
class RunResult:
    status: str
    before_count: Optional[int]
    after_count: Optional[int]
    worklist: list[WorklistItem] = field(default_factory=list)
    summary_path: str = ""
    cve_summary: str = ""
    venv_dir: Optional[str] = None
