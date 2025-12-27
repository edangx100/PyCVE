from __future__ import annotations

import json
import os
import shutil
from typing import Optional

from . import audit
from .models import RunContext


def init_artifacts_dir(artifacts_root: Optional[str], run_id: str) -> str:
    """Create (or reuse) the run-scoped artifacts directory."""
    artifacts_root = artifacts_root or os.path.join(os.getcwd(), "artifacts")
    artifacts_root = os.path.abspath(artifacts_root)
    # Ensure both the root and run-specific directories exist.
    os.makedirs(artifacts_root, exist_ok=True)
    artifacts_dir = os.path.join(artifacts_root, run_id)
    os.makedirs(artifacts_dir, exist_ok=True)
    return artifacts_dir


def write_text_file(path: str, content: str) -> bool:
    """Write text to disk."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return True
    except OSError:
        return False


def write_json_file(path: str, payload: object) -> bool:
    """Write JSON to disk with stable formatting."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        return False
    return True


def read_json_file(path: str) -> Optional[object]:
    """Read JSON from disk, returning None on failure."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def write_audit_json(
    artifacts_dir: str,
    filename: str,
    content: str,
) -> tuple[bool, str]:
    """Write an audit JSON artifact and return its path."""
    path = os.path.join(artifacts_dir, filename)
    ok = write_text_file(path, content)
    return ok, path


def write_audit_alias(source_path: str, alias_path: str) -> bool:
    """Create or replace a pip_audit.json alias."""
    # Use a copy to keep "pip_audit.json" in sync with the chosen source.
    try:
        shutil.copyfile(source_path, alias_path)
    except OSError:
        return False
    return True


def stub_audit_payload(reason_code: str, reason_detail: str) -> dict[str, object]:
    """Build the stub payload for skipped/failed pip-audit artifacts."""
    return {
        "skipped": True,
        "reason_code": reason_code,
        "reason_detail": reason_detail,
        "results": [],
    }


def stub_cve_payload(reason_code: str, reason_detail: str) -> dict[str, object]:
    """Build the stub payload for skipped/failed CVE status artifacts."""
    return {
        "skipped": True,
        "reason_code": reason_code,
        "reason_detail": reason_detail,
        "before": [],
        "after": [],
        "fixed": [],
        "remaining": [],
    }


def ensure_stub_audit_artifacts(
    artifacts_dir: str,
    reason_code: str,
    reason_detail: str,
) -> dict[str, str]:
    """Ensure baseline/final audit artifacts exist, writing stubs if needed."""
    payload = stub_audit_payload(reason_code, reason_detail)
    before_path = os.path.join(artifacts_dir, "pip_audit_before.json")
    after_path = os.path.join(artifacts_dir, "pip_audit_after.json")
    alias_path = os.path.join(artifacts_dir, "pip_audit.json")

    # Write missing baseline/final JSON so downstream reads always succeed.
    if not os.path.isfile(before_path):
        write_json_file(before_path, payload)
    if not os.path.isfile(after_path):
        write_json_file(after_path, payload)
    if not os.path.isfile(alias_path):
        # Prefer the "after" audit as the main alias when available.
        if os.path.isfile(after_path):
            if not write_audit_alias(after_path, alias_path):
                write_json_file(alias_path, payload)
        else:
            write_json_file(alias_path, payload)

    return {"before": before_path, "after": after_path, "alias": alias_path}


def ensure_stub_cve_status(
    artifacts_dir: str,
    reason_code: str,
    reason_detail: str,
) -> str:
    """Ensure cve_status.json exists, writing a stub if needed."""
    cve_path = os.path.join(artifacts_dir, "cve_status.json")
    if os.path.isfile(cve_path):
        return cve_path
    # Provide a minimal payload so readers don't fail on missing files.
    payload = stub_cve_payload(reason_code, reason_detail)
    write_json_file(cve_path, payload)
    return cve_path


def write_summary(artifacts_dir: str, summary_text: str) -> tuple[bool, str]:
    """Write SUMMARY.md to the artifacts directory."""
    summary_path = os.path.join(artifacts_dir, "SUMMARY.md")
    ok = write_text_file(summary_path, summary_text)
    return ok, summary_path


def write_stub_run_artifacts(
    context: RunContext,
    status: str,
    reason_code: str,
    reason_detail: str,
    summary_text: str,
) -> Optional[str]:
    """Write stub artifacts + summary for skipped/failed runs."""
    # Ensure required artifacts exist even when the run does not proceed.
    ensure_stub_audit_artifacts(
        artifacts_dir=context.artifacts_dir,
        reason_code=reason_code,
        reason_detail=reason_detail,
    )
    ensure_stub_cve_status(
        artifacts_dir=context.artifacts_dir,
        reason_code=reason_code,
        reason_detail=reason_detail,
    )
    summary_ok, summary_path = write_summary(context.artifacts_dir, summary_text)
    if summary_ok:
        return summary_path
    return None


def write_cve_status(
    before_audit_path: str,
    after_audit_path: str,
    artifacts_dir: str,
) -> tuple[bool, Optional[int], Optional[int]]:
    """Write cve_status.json and return fixed/remaining counts."""
    before_payload = read_json_file(before_audit_path)
    after_payload = read_json_file(after_audit_path)
    if before_payload is None or after_payload is None:
        return False, None, None

    # Compute before/after delta and persist the status payload.
    status_payload, fixed_count, remaining_count = build_cve_status_payload(
        before_payload,
        after_payload,
    )
    cve_path = os.path.join(artifacts_dir, "cve_status.json")
    try:
        with open(cve_path, "w", encoding="utf-8") as handle:
            json.dump(status_payload, handle, indent=2)
    except OSError:
        return False, None, None
    return True, fixed_count, remaining_count


def build_cve_status_payload(
    before_payload: object,
    after_payload: object,
) -> tuple[dict[str, list[dict[str, object]]], int, int]:
    """Build the before/after/fixed/remaining structure for cve_status.json."""
    before_records = collect_vuln_records(before_payload)
    after_records = collect_vuln_records(after_payload)

    # Track what remains by keying after-records for fast membership tests.
    after_keys = {vuln_record_key(record) for record in after_records}

    fixed_records: list[dict[str, object]] = []
    for record in before_records:
        if vuln_record_key(record) in after_keys:
            continue
        fixed_entry = dict(record)
        fixed_entry["status"] = "fixed"
        fixed_records.append(fixed_entry)

    remaining_records: list[dict[str, object]] = []
    for record in after_records:
        remaining_entry = dict(record)
        remaining_entry["status"] = "remaining"
        remaining_records.append(remaining_entry)

    payload = {
        "before": before_records,
        "after": after_records,
        "fixed": fixed_records,
        "remaining": remaining_records,
    }
    return payload, len(fixed_records), len(remaining_records)


def collect_vuln_records(payload: object) -> list[dict[str, object]]:
    """Extract vulnerability records from pip-audit JSON output."""
    records: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    # Normalize different pip-audit JSON shapes into a flat record list.
    for item in audit.extract_audit_items(payload):
        name = item.get("name") or item.get("package") or item.get("dependency")
        if not name:
            continue
        package = str(name)
        vulns = item.get("vulns")
        if vulns is None:
            vulns = item.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            # Support multiple schema keys for advisory IDs and fix versions.
            advisory_id = vuln.get("id") or vuln.get("cve") or vuln.get("name")
            advisory_id = str(advisory_id).strip() if advisory_id else ""
            aliases = audit.unique_strings(audit.string_list(vuln.get("aliases")))
            fix_versions = audit.string_list(
                vuln.get("fix_versions") or vuln.get("fixed_versions")
            )
            fix_versions = audit.unique_strings(fix_versions)

            if not advisory_id and aliases:
                advisory_id = aliases[0]
            if not advisory_id:
                advisory_id = "unknown"

            # Prefer CVE IDs in cve_ids and ensure the advisory itself is included.
            cve_ids = [alias for alias in aliases if str(alias).upper().startswith("CVE-")]
            if advisory_id.upper().startswith("CVE-"):
                cve_ids = audit.unique_strings([advisory_id] + cve_ids)
            else:
                cve_ids = audit.unique_strings(cve_ids)

            record = {
                "package": package,
                "advisory_id": advisory_id,
                "cve_ids": cve_ids,
            }
            if aliases:
                record["aliases"] = aliases
            if fix_versions:
                record["fix_versions"] = fix_versions

            key = vuln_record_key(record)
            # De-duplicate across package+advisory to keep the status payload stable.
            if key in seen:
                continue
            seen.add(key)
            records.append(record)

    return records


def vuln_record_key(record: dict[str, object]) -> tuple[str, str]:
    """Build a stable key for comparing vulnerability records."""
    package = str(record.get("package") or "")
    advisory_id = str(record.get("advisory_id") or "")
    # Normalize package names so comparisons are consistent across formats.
    return audit.normalize_name(package), advisory_id
