from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
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


def venv_python(venv_dir: str, force_posix: bool = False) -> str:
    """Return the venv interpreter path for the current platform."""
    if not force_posix and os.name == "nt":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return posixpath.join(venv_dir, "bin", "python")


@dataclass
class CommandOutput:
    stdout: str
    stderr: str
    returncode: int


def _command_to_string(args: list[str]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


def run_command(
    args: list[str],
    cwd: Optional[str] = None,
    workspace: Optional[object] = None,
) -> CommandOutput:
    """Run a subprocess and always capture stdout/stderr."""
    if workspace is None:
        result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
        return CommandOutput(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    command = _command_to_string(args)
    result = workspace.execute_command(command, cwd=cwd)
    return CommandOutput(
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.exit_code,
    )


def ensure_venv(venv_dir: str) -> None:
    """Create a venv with pip if it doesn't exist yet."""
    if os.path.isdir(venv_dir):
        return
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)


def workspace_dir_exists(workspace: object, path: str) -> bool:
    """Check if a directory exists inside a workspace."""
    result = run_command(["test", "-d", path], workspace=workspace)
    return result.returncode == 0


def ensure_workspace_venv(venv_dir: str, workspace_dir: str, workspace: object) -> Optional[str]:
    """Create a venv inside the workspace, returning an error string on failure."""
    python_bin = os.getenv("DOCKER_PYTHON_BIN", "python")
    result = run_command([python_bin, "-m", "venv", venv_dir], cwd=workspace_dir, workspace=workspace)
    if result.returncode != 0:
        return result.stderr.strip() or "unable to create venv in workspace"
    return None


def run_baseline_audit(
    requirements_path: str,
    workspace_dir: str,
    workspace: Optional[object] = None,
) -> BaselineAuditResult:
    """Create/prepare a venv and run the baseline pip-audit."""
    venv_dir = (
        posixpath.join(workspace_dir, ".venv")
        if workspace is not None
        else os.path.join(workspace_dir, ".venv")
    )
    created_venv = False
    # Track whether we created a fresh venv so callers can clean up if needed.
    if workspace is None:
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
    else:
        if not workspace_dir_exists(workspace, venv_dir):
            created_venv = True
            error = ensure_workspace_venv(venv_dir, workspace_dir, workspace)
            if error:
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
                    error=error,
                )

    install_cmd = [
        venv_python(venv_dir, force_posix=workspace is not None),
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "pip-audit",
    ]
    # Install pip-audit inside the isolated venv before running the audit.
    install_result = run_command(install_cmd, cwd=workspace_dir, workspace=workspace)
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

    audit = run_pip_audit_json(venv_dir, requirements_path, workspace=workspace)
    return BaselineAuditResult(
        ok=audit.ok,
        audit=audit,
        venv_dir=venv_dir,
        created_venv=created_venv,
    )


def run_final_audit(
    requirements_path: str,
    workspace_dir: str,
    workspace: Optional[object] = None,
) -> FinalAuditResult:
    """Run a final pip-audit using the existing venv."""
    venv_dir = (
        posixpath.join(workspace_dir, ".venv")
        if workspace is not None
        else os.path.join(workspace_dir, ".venv")
    )
    if workspace is None:
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
    else:
        if not workspace_dir_exists(workspace, venv_dir):
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
    audit = run_pip_audit_json(venv_dir, requirements_path, workspace=workspace)
    return FinalAuditResult(ok=audit.ok, audit=audit, venv_dir=venv_dir)


def run_pip_audit_json(
    venv_dir: str,
    requirements_path: str,
    workspace: Optional[object] = None,
) -> AuditRunResult:
    """Run pip-audit and return JSON output + stderr notes."""
    cwd = (
        posixpath.dirname(requirements_path)
        if workspace is not None
        else os.path.dirname(requirements_path)
    )
    audit_cmd = [
        venv_python(venv_dir, force_posix=workspace is not None),
        "-m",
        "pip_audit",
        "-r",
        requirements_path,
        "--format",
        "json",
    ]
    audit_result = run_command(
        audit_cmd,
        cwd=cwd,
        workspace=workspace,
    )
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
