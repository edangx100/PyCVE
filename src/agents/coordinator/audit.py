from __future__ import annotations

import json
import os
import re
import subprocess
import venv
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuditRunResult:
    ok: bool
    audit_json: Optional[str]
    returncode: Optional[int]
    stderr: list[str] = field(default_factory=list)
    vuln_count: Optional[int] = None


@dataclass
class BaselineAuditResult:
    ok: bool
    audit: AuditRunResult
    venv_dir: str
    created_venv: bool
    error: Optional[str] = None
    error_stderr: Optional[str] = None


@dataclass
class FinalAuditResult:
    ok: bool
    audit: AuditRunResult
    venv_dir: str
    venv_missing: bool = False


def venv_python(venv_dir: str) -> str:
    """Return the venv interpreter path for the current platform."""
    if os.name == "nt":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def run_command(
    args: list[str],
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess and always capture stdout/stderr."""
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


def ensure_venv(venv_dir: str) -> None:
    """Create a venv with pip if it doesn't exist yet."""
    if os.path.isdir(venv_dir):
        return
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)


def run_baseline_audit(
    requirements_path: str,
    workspace_dir: str,
) -> BaselineAuditResult:
    """Create/prepare a venv and run the baseline pip-audit."""
    venv_dir = os.path.join(workspace_dir, ".venv")
    created_venv = False
    # Track whether we created a fresh venv so callers can clean up if needed.
    if not os.path.isdir(venv_dir):
        created_venv = True
    try:
        ensure_venv(venv_dir)
    except Exception as exc:
        audit = AuditRunResult(
            ok=False,
            audit_json=None,
            returncode=None,
            stderr=[],
            vuln_count=None,
        )
        return BaselineAuditResult(
            ok=False,
            audit=audit,
            venv_dir=venv_dir,
            created_venv=created_venv,
            error=f"unable to create venv: {exc}",
        )

    install_cmd = [
        venv_python(venv_dir),
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "pip-audit",
    ]
    # Install pip-audit inside the isolated venv before running the audit.
    install_result = run_command(install_cmd, cwd=workspace_dir)
    if install_result.returncode != 0:
        audit = AuditRunResult(
            ok=False,
            audit_json=None,
            returncode=install_result.returncode,
            stderr=[],
            vuln_count=None,
        )
        return BaselineAuditResult(
            ok=False,
            audit=audit,
            venv_dir=venv_dir,
            created_venv=created_venv,
            error=f"pip-audit install returned {install_result.returncode}",
            error_stderr=install_result.stderr.strip() or None,
        )

    audit = run_pip_audit_json(venv_dir, requirements_path)
    return BaselineAuditResult(
        ok=audit.ok,
        audit=audit,
        venv_dir=venv_dir,
        created_venv=created_venv,
    )


def run_final_audit(
    requirements_path: str,
    workspace_dir: str,
) -> FinalAuditResult:
    """Run a final pip-audit using the existing venv."""
    venv_dir = os.path.join(workspace_dir, ".venv")
    if not os.path.isdir(venv_dir):
        audit = AuditRunResult(
            ok=False,
            audit_json=None,
            returncode=None,
            stderr=[],
            vuln_count=None,
        )
        return FinalAuditResult(
            ok=False,
            audit=audit,
            venv_dir=venv_dir,
            venv_missing=True,
        )
    audit = run_pip_audit_json(venv_dir, requirements_path)
    return FinalAuditResult(ok=audit.ok, audit=audit, venv_dir=venv_dir)


def run_pip_audit_json(
    venv_dir: str,
    requirements_path: str,
) -> AuditRunResult:
    """Run pip-audit and return JSON output + stderr notes."""
    audit_cmd = [
        venv_python(venv_dir),
        "-m",
        "pip_audit",
        "-r",
        requirements_path,
        "--format",
        "json",
    ]
    audit_result = run_command(audit_cmd, cwd=os.path.dirname(requirements_path))
    stderr_notes: list[str] = []
    # Preserve any stderr output as a note while still parsing stdout JSON.
    if audit_result.stderr.strip():
        stderr_notes.append(audit_result.stderr.strip())
    stdout = audit_result.stdout.strip()
    # Treat missing stdout as a failed audit run (no JSON to parse).
    if not stdout:
        return AuditRunResult(
            ok=False,
            audit_json=None,
            returncode=audit_result.returncode,
            stderr=stderr_notes,
            vuln_count=None,
        )
    vuln_count = count_vulnerabilities(stdout)
    return AuditRunResult(
        ok=True,
        audit_json=stdout,
        returncode=audit_result.returncode,
        stderr=stderr_notes,
        vuln_count=vuln_count,
    )


def count_vulnerabilities(raw_json: str) -> Optional[int]:
    """Best-effort count of vulnerabilities from pip-audit JSON output."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError:
        return None

    items = extract_audit_items(payload)
    total = 0
    for item in items:
        # Handle both legacy and current schema keys for vulnerabilities.
        vulns = item.get("vulns")
        if vulns is None:
            vulns = item.get("vulnerabilities")
        if isinstance(vulns, list):
            total += len(vulns)
    return total


def count_package_vulns(payload: object, package_name: str) -> Optional[int]:
    """Count vulnerabilities for a specific package name."""
    normalized_target = normalize_name(package_name)
    items = extract_audit_items(payload)
    if not items:
        return None
    total = 0
    found = False
    for item in items:
        name = item.get("name") or item.get("package") or item.get("dependency")
        if not name:
            continue
        # Compare normalized names so "pkg-name" matches "pkg_name".
        if normalize_name(str(name)) != normalized_target:
            continue
        found = True
        vulns = item.get("vulns")
        if vulns is None:
            vulns = item.get("vulnerabilities")
        if isinstance(vulns, list):
            total += len(vulns)
    if not found:
        # Package missing from audit output; treat as zero vulns (not unknown).
        return 0
    return total


def normalize_name(name: str) -> str:
    """Normalize package names for reliable comparisons."""
    return re.sub(r"[-_.]+", "-", name).lower()


def extract_audit_items(payload: object) -> list[dict]:
    """Return a list of dependency dicts from pip-audit JSON output."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        # Support multiple pip-audit JSON shapes.
        for key in ("dependencies", "results"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        return [payload]
    return []


def string_list(values: object) -> list[str]:
    """Normalize an input into a list of strings."""
    if isinstance(values, list):
        return [str(value) for value in values if value]
    if isinstance(values, str):
        return [values]
    return []


def unique_strings(items: list[str]) -> list[str]:
    """Return a stable, de-duplicated list of strings."""
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        # Preserve original order while filtering duplicates.
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique
