#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import threading
import time
import uuid
from typing import Generator, Optional

from dotenv import load_dotenv
from openhands.sdk import Agent, Conversation, LLM, Tool
from openhands.sdk.event import ObservationEvent
from openhands.tools.delegate import DelegateTool
from openhands.tools.terminal import TerminalTool

from . import artifacts, audit, reporting, requirements_parser
from .models import (
    RequirementEntry,
    RequirementsParseResult,
    RunContext,
    RunResult,
    WorklistItem,
)
from src.agents.fixer import FixerTask, register_fixer_agent


class Coordinator:
    """Orchestrate cloning + dependency scanning through an OpenHands agent."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None) -> None:
        # Load OpenRouter credentials and model config for the Coordinator agent.
        load_dotenv()
        api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY not found in .env")

        model = model or os.getenv("COORDINATOR_OPENROUTER_MODEL", "openai/gpt-3.5-turbo")
        openrouter_model = f"openrouter/{model}"
        self.llm = LLM(model=openrouter_model, api_key=api_key)
        self.agent = Agent(
            llm=self.llm,
            tools=[
                # TerminalTool for git/pip-audit runs; DelegateTool to spawn the Fixer.
                Tool(
                    name=TerminalTool.name,
                    params={"terminal_type": "subprocess"},
                ),
                Tool(name=DelegateTool.name),
            ],
        )
        self.latest_worklist: list[WorklistItem] = []
        self.latest_patch_notes: str = ""
        self.patch_notes_paths: list[str] = []
        self.latest_cve_summary: str = "CVE summary: pending"
        self.latest_summary: str = ""
        self.latest_summary_path: str = ""
        self.latest_artifacts_dir: str = ""
        register_fixer_agent()

    def clone_repo_stream(
        self,
        # Required input for git clone; validated before any workspace work starts.
        repo_url: str,
        workspace_root: str,
        run_id: Optional[str] = None,
        artifacts_root: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """Clone a repo in an agent workspace, then parse requirements and run pip-audit."""
        # Stream a git clone (and follow-on parse) while the agent runs in OpenHands.
        repo_url_value = repo_url.strip() if repo_url else ""
        repo_url_display = repo_url_value or "unknown"
        run_id = run_id or self._new_run_id()
        run_started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        workspace_root = os.path.abspath(workspace_root)
        workspace_dir = os.path.join(workspace_root, run_id)
        repo_dir = os.path.join(workspace_dir, "repo")
        # Reset per-run state so callers always see the latest artifacts.
        self.latest_patch_notes = ""
        self.patch_notes_paths = []
        self.latest_cve_summary = "CVE summary: pending"
        self.latest_summary = ""
        self.latest_summary_path = ""
        self.latest_artifacts_dir = ""

        # Each run gets an isolated workspace to keep artifacts and venvs separate.
        os.makedirs(workspace_dir, exist_ok=True)
        artifacts_dir = artifacts.init_artifacts_dir(artifacts_root, run_id)
        self.latest_artifacts_dir = artifacts_dir
        context = RunContext(
            run_id=run_id,
            run_started_at=run_started_at,
            repo_url=repo_url_display,
            repo_dir=repo_dir,
            workspace_root=workspace_root,
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
        )

        yield f"[artifacts] Directory: {artifacts_dir}"
        yield f"[clone] Run ID: {run_id}"
        yield f"[clone] Workspace: {workspace_dir}"
        yield f"[clone] Repo URL: {repo_url_display}"

        if not repo_url_value:
            yield "[clone] FAILED: repo URL is required."
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="missing_repo_url",
                reason_detail="repo URL is required",
            )
            yield "[run] COMPLETE: failed"
            return

        # Ask the agent to run the clone command in the workspace directory.
        conversation = Conversation(agent=self.agent, workspace=workspace_dir)
        safe_url = shlex.quote(repo_url_value)
        clone_cmd = f"git clone --progress {safe_url} repo"
        task = (
            "You are the Coordinator agent. Use TerminalTool to clone the repo. "
            f"Run exactly this command: {clone_cmd}. "
            "Return a short success or failure message once the clone completes."
        )

        conversation.send_message(task)

        run_errors = []
        terminal_error = False
        # Collect run exceptions and terminal failures separately for reporting.

        def _run() -> None:
            # Run the agent loop in a background thread so we can stream events.
            try:
                conversation.run()
            except Exception as exc:
                run_errors.append(exc)

        """
        Main thread                         Background thread
        -----------                         -----------------
        conversation.send_message(task)        |
        runner = Thread(target=_run)           |
        runner.start()    -------------------->|  _run() calls conversation.run()
        while runner.is_alive():               |  (blocking: LLM I/O + TerminalTool)
        _drain_events(conversation)            |  conversation.state.events <- events
        yield lines to caller                  |  (terminal output, progress)
        sleep(0.2)                             |
                                               | runner finishes (conversation.run returns / errors)
        runner.join()  (wait for completion) <-|
        final _drain_events(conversation)      |
        continue with post-run logic           |
        """

        runner = threading.Thread(target=_run, daemon=True)
        runner.start()

        # Drain terminal output as events arrive.
        events_seen = 0
        while runner.is_alive():
            events_seen, new_error, lines = self._drain_events(conversation, events_seen)
            terminal_error = terminal_error or new_error
            for line in lines:
                prefix = "[clone][error]" if new_error else "[clone]"
                yield f"{prefix} {line}"
            time.sleep(0.2)

        runner.join()

        # Final drain after the agent finishes.
        events_seen, new_error, lines = self._drain_events(conversation, events_seen)
        terminal_error = terminal_error or new_error
        for line in lines:
            prefix = "[clone][error]" if new_error else "[clone]"
            yield f"{prefix} {line}"

        if run_errors:
            yield f"[clone] FAILED: {run_errors[0]}"
            # Persist stub artifacts so the UI still has downloadable files on failure.
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="clone_failed",
                reason_detail=str(run_errors[0]),
            )
            yield "[run] COMPLETE: failed"
            return

        if terminal_error:
            yield "[clone] FAILED: git clone reported an error."
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="clone_failed",
                reason_detail="git clone reported an error",
            )
            yield "[run] COMPLETE: failed"
            return

        if os.path.isdir(os.path.join(repo_dir, ".git")):
            yield f"[clone] SUCCESS: {repo_dir}"
        else:
            # Protect downstream steps from running on an incomplete checkout.
            yield "[clone] FAILED: repo directory not found after clone."
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="clone_failed",
                reason_detail="repo directory not found after clone",
            )
            yield "[run] COMPLETE: failed"
            return

        # Parse requirements.txt and gate on directives before later stages.
        requirements_path = os.path.join(repo_dir, "requirements.txt")
        if not os.path.isfile(requirements_path):
            yield f"[parse] SKIPPED: requirements.txt not found at {requirements_path}"
            self._write_stub_run_artifacts(
                context=context,
                status="SKIPPED",
                reason_code="missing_requirements",
                reason_detail="requirements.txt not found",
            )
            yield "[run] COMPLETE: skipped"
            return

        yield f"[parse] Found requirements.txt at {requirements_path}"
        parse_result = requirements_parser.parse_requirements_file(requirements_path)
        if parse_result.editable:
            yield f"[parse] Editable requirements: {len(parse_result.editable)}"
            for entry in parse_result.editable:
                spec = f" {entry.spec}" if entry.spec else ""
                yield f"[parse][editable] L{entry.line_no}: {entry.name}{spec}"
        else:
            yield "[parse] Editable requirements: 0"

        if parse_result.unknown:
            yield f"[parse] Unsupported/unknown lines: {len(parse_result.unknown)}"
            for entry in parse_result.unknown:
                yield f"[parse][unknown] L{entry.line_no}: {entry.raw}"

        if parse_result.directives:
            yield f"[parse] Directives found: {len(parse_result.directives)}"
            for entry in parse_result.directives:
                yield f"[parse][directive] L{entry.line_no}: {entry.raw}"
            if parse_result.skip_reason:
                yield f"[parse] SKIPPED: {parse_result.skip_reason}"
            # Skip processing when directives imply non-editable requirements sources.
            self._write_stub_run_artifacts(
                context=context,
                status="SKIPPED",
                reason_code="directives_detected",
                reason_detail=parse_result.skip_reason or "directive detected",
            )
            yield "[run] COMPLETE: skipped"
            return

        scan_ok = yield from self.run_pip_audit_stream(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
        )
        worklist: list[WorklistItem] = []
        before_count: Optional[int] = None
        after_count: Optional[int] = None
        final_ok = True
        if scan_ok:
            # Build and emit the direct-dependency worklist based on the audit JSON.
            audit_path = os.path.join(artifacts_dir, "pip_audit_before.json")
            worklist = self.build_worklist_from_audit(audit_path, parse_result)
            self.latest_worklist = worklist
            yield f"[worklist] Direct requirements: {len(parse_result.editable)}"
            yield f"[worklist] Vulnerable direct packages: {len(worklist)}"
            for item in worklist:
                # Format a terse worklist line for streaming logs.
                spec = item.spec or "(unpinned)"
                vuln_ids = ", ".join(item.vuln_ids) if item.vuln_ids else "unknown"
                fix_versions = ", ".join(item.fix_versions) if item.fix_versions else "unknown"
                yield f"[worklist] {item.name} {spec} -> {vuln_ids} | fixes: {fix_versions}"
            if worklist:
                # Task 11: iterate through the full worklist and fix packages serially.
                # Map normalized names to requirement entries so fixer prompts have line context.
                entry_map = {
                    audit.normalize_name(entry.name): entry for entry in parse_result.editable
                }
                total = len(worklist)
                yield f"[fix] Starting fix loop: {total} package(s)"
                for index, target in enumerate(worklist, start=1):
                    entry = entry_map.get(audit.normalize_name(target.name))
                    # Emit progress so the UI can render a package-level progress bar.
                    yield f"[fix] Progress: {index}/{total} ({target.name})"
                    yield f"[fix] Delegating package: {target.name}"
                    patch_notes, patch_path = self._run_fixer_once(
                        item=target,
                        entry=entry,
                        requirements_path=requirements_path,
                        artifacts_dir=artifacts_dir,
                        workspace_dir=workspace_dir,
                    )
                    if os.path.isfile(patch_path):
                        # Track patch note paths so downstream UI can list all artifacts.
                        self.patch_notes_paths.append(patch_path)
                    if patch_notes is not None:
                        # Spot-check the fix by re-running pip-audit and updating patch notes.
                        before_audit_path = os.path.join(
                            artifacts_dir,
                            "pip_audit_before.json",
                        )
                        backup_path = os.path.join(
                            os.path.dirname(requirements_path),
                            "requirements_before.txt",
                        )
                        status, before_count, after_count, reverted = reporting.spot_check_fix(
                            package_name=target.name,
                            requirements_path=requirements_path,
                            backup_path=backup_path,
                            artifacts_dir=artifacts_dir,
                            workspace_dir=workspace_dir,
                            patch_notes_path=patch_path,
                            before_audit_path=before_audit_path,
                        )
                        before_display = "unknown" if before_count is None else str(before_count)
                        after_display = "unknown" if after_count is None else str(after_count)
                        revert_note = " (reverted)" if reverted else ""
                        yield (
                            f"[verify] {target.name}: {status} "
                            f"(before {before_display}, after {after_display}){revert_note}"
                        )
                        # Cache patch notes for the UI to display the latest fix result.
                        self.latest_patch_notes = reporting.read_text_file(patch_path)
                        yield f"[fix] Patch notes saved: {patch_path}"
                    else:
                        self.latest_patch_notes = ""
                        yield "[fix] Patch notes not generated"
            # After all fixes, run a final audit and write the "after" artifacts.
            final_ok, before_count, after_count = yield from self.run_final_audit_stream(
                requirements_path=requirements_path,
                workspace_dir=workspace_dir,
                artifacts_dir=artifacts_dir,
                before_audit_path=audit_path,
            )
            if final_ok:
                # Build cve_status.json and surface fixed/remaining counts to the UI.
                cve_path = os.path.join(artifacts_dir, "cve_status.json")
                cve_ok, fixed_count, remaining_count = artifacts.write_cve_status(
                    before_audit_path=audit_path,
                    after_audit_path=os.path.join(artifacts_dir, "pip_audit_after.json"),
                    artifacts_dir=artifacts_dir,
                )
                if cve_ok:
                    yield f"[cve] Saved artifact: {cve_path}"
                    fixed_display = "unknown" if fixed_count is None else str(fixed_count)
                    remaining_display = "unknown" if remaining_count is None else str(remaining_count)
                    self.latest_cve_summary = (
                        f"CVE summary: fixed {fixed_display}, remaining {remaining_display}"
                    )
                    yield (
                        f"[cve] Fixed: {fixed_display} | Remaining: {remaining_display}"
                    )
                else:
                    self.latest_cve_summary = "CVE summary: unavailable"
                    yield "[cve] FAILED: unable to write cve_status.json"
                    # Ensure the CVE artifact exists even if the normal write failed.
                    artifacts.ensure_stub_cve_status(
                        artifacts_dir=artifacts_dir,
                        reason_code="cve_status_failed",
                        reason_detail="unable to write cve_status.json",
                    )
            else:
                self.latest_cve_summary = "CVE summary: unavailable"
                # Backfill stub audit + CVE artifacts so downloads remain available.
                artifacts.ensure_stub_audit_artifacts(
                    artifacts_dir=artifacts_dir,
                    reason_code="final_audit_failed",
                    reason_detail="final pip-audit failed",
                )
                artifacts.ensure_stub_cve_status(
                    artifacts_dir=artifacts_dir,
                    reason_code="final_audit_failed",
                    reason_detail="final pip-audit failed",
                )
            summary_status = "SUCCESS" if scan_ok and final_ok else "FAILED"
            result = RunResult(
                status=summary_status,
                before_count=before_count,
                after_count=after_count,
                worklist=worklist,
                venv_dir=os.path.join(workspace_dir, ".venv"),
            )
            summary_text = reporting.build_summary_text(context, result)
            summary_ok, summary_path = artifacts.write_summary(artifacts_dir, summary_text)
            if summary_ok:
                self.latest_summary = summary_text
                self.latest_summary_path = summary_path
                yield f"[summary] Saved artifact: {summary_path}"
            else:
                yield "[summary] FAILED: unable to write SUMMARY.md"
        else:
            # Clear any previous worklist if the scan failed.
            self.latest_worklist = []
            self.latest_cve_summary = "CVE summary: unavailable"
            # Write stub artifacts + summary to keep outputs consistent for failed runs.
            self._write_stub_run_artifacts(
                context=context,
                status="FAILED",
                reason_code="baseline_audit_failed",
                reason_detail="baseline pip-audit failed",
            )
        status = "success" if scan_ok and final_ok else "failed"
        yield f"[run] COMPLETE: {status}"

    @staticmethod
    def _new_run_id() -> str:
        return f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    def _write_stub_run_artifacts(
        self,
        context: RunContext,
        status: str,
        reason_code: str,
        reason_detail: str,
    ) -> None:
        """Write stub artifacts + summary for skipped/failed runs."""
        result = RunResult(
            status=status,
            before_count=None,
            after_count=None,
            worklist=[],
            venv_dir=None,
        )
        summary_text = reporting.build_summary_text(context, result)
        summary_path = artifacts.write_stub_run_artifacts(
            context=context,
            status=status,
            reason_code=reason_code,
            reason_detail=reason_detail,
            summary_text=summary_text,
        )
        if summary_path:
            self.latest_summary = summary_text
            self.latest_summary_path = summary_path
        self.latest_cve_summary = (
            "CVE summary: skipped" if status.upper() == "SKIPPED" else "CVE summary: unavailable"
        )

    @staticmethod
    def _drain_events(
        conversation: Conversation,
        events_seen: int,
    ) -> tuple[int, bool, list[str]]:
        """Collect new terminal output lines since the last drain call."""
        # Extract terminal output from any new events since last drain.
        lines: list[str] = []
        new_error = False

        events = list(getattr(conversation.state, "events", []))
        for event in events[events_seen:]:
            text, is_error = Coordinator._extract_terminal_output(event)
            if is_error:
                new_error = True
            if not text:
                continue
            for line in Coordinator._split_output(text):
                lines.append(line)

        return len(events), new_error, lines

    @staticmethod
    def _extract_terminal_output(event: object) -> tuple[Optional[str], bool]:
        """Return terminal text + error flag if the event is a TerminalTool observation."""
        # Pull terminal output from ObservationEvent if it came from TerminalTool.
        if not isinstance(event, ObservationEvent):
            return None, False
        if getattr(event, "tool_name", None) != TerminalTool.name:
            return None, False

        obs = getattr(event, "observation", None)
        if obs is None:
            return None, False

        is_error = bool(getattr(obs, "is_error", False))
        text = Coordinator._observation_text(obs)
        return text, is_error

    @staticmethod
    def _observation_text(observation: object) -> Optional[str]:
        """Normalize observation payloads into a single text blob."""
        # Observation payloads vary; check common fields before falling back.
        parts = []
        if isinstance(observation, dict):
            for key in ("stdout", "stderr", "content", "output", "text"):
                value = observation.get(key)
                if value:
                    parts.append(value)
        else:
            for attr in ("stdout", "stderr", "content", "output", "text"):
                value = getattr(observation, attr, None)
                if value:
                    parts.append(value)

        if not parts:
            return str(observation)

        return "\n".join(str(part) for part in parts if part)

    @staticmethod
    def _split_output(text: str) -> list[str]:
        """Normalize newlines and drop empty output lines."""
        # Normalize CRLF and return non-empty output lines.
        cleaned = text.replace("\r", "\n")
        return [line.rstrip("\n") for line in cleaned.splitlines() if line.strip()]

    def build_worklist_from_audit(
        self,
        audit_path: str,
        parse_result: RequirementsParseResult,
    ) -> list[WorklistItem]:
        """Build a direct-dependency worklist from pip-audit JSON output."""
        try:
            with open(audit_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return []

        # Map normalized direct requirement names for fast lookups.
        direct_map = {
            audit.normalize_name(entry.name): entry for entry in parse_result.editable
        }
        worklist: list[WorklistItem] = []
        seen: set[str] = set()

        for item in audit.extract_audit_items(payload):
            name = item.get("name") or item.get("package") or item.get("dependency")
            if not name:
                continue
            normalized = audit.normalize_name(str(name))
            # Only keep vulnerabilities tied to direct requirements.
            if normalized not in direct_map:
                continue
            if normalized in seen:
                continue

            entry = direct_map[normalized]
            vulns = item.get("vulns")
            if vulns is None:
                vulns = item.get("vulnerabilities")
            # Skip clean dependencies so the worklist stays vulnerability-only.
            if not isinstance(vulns, list) or not vulns:
                continue
            vuln_ids: list[str] = []
            fix_versions: list[str] = []
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                # Collect IDs and aliases for display, plus any fix versions.
                vuln_id = vuln.get("id") or vuln.get("cve") or vuln.get("name")
                if vuln_id:
                    vuln_ids.append(str(vuln_id))
                for alias in audit.string_list(vuln.get("aliases")):
                    vuln_ids.append(alias)
                fixes = vuln.get("fix_versions")
                if fixes is None:
                    fixes = vuln.get("fixed_versions")
                for fix in audit.string_list(fixes):
                    fix_versions.append(fix)

            # Prefer the audited version, else fall back to the requirement spec.
            current_version = str(item.get("version") or "").strip()
            if not current_version:
                current_version = entry.spec or "unknown"

            worklist.append(
                WorklistItem(
                    name=entry.name,
                    spec=entry.spec,
                    current_version=current_version,
                    vuln_ids=audit.unique_strings(vuln_ids),
                    fix_versions=audit.unique_strings(fix_versions),
                    is_editable=True,
                    skip_reason=None,
                )
            )
            seen.add(normalized)

        return worklist

    def worklist_table_rows(self) -> list[list[str]]:
        """Format the latest worklist into UI table rows."""
        rows: list[list[str]] = []
        for item in self.latest_worklist:
            # Show the first suggested fix version as a quick hint.
            vuln_ids = ", ".join(item.vuln_ids) if item.vuln_ids else "unknown"
            suggested_fix = f">={item.fix_versions[0]}" if item.fix_versions else "unknown"
            rows.append(
                [
                    item.name,
                    vuln_ids,
                    item.current_version,
                    suggested_fix,
                ]
            )
        return rows

    def run_pip_audit_stream(
        self,
        requirements_path: str,
        workspace_dir: str,
        artifacts_dir: str,
    ) -> Generator[str, None, None]:
        """Install pip-audit into a venv, run it, and stream progress lines."""
        yield "[scan] Starting baseline pip-audit"

        venv_dir = os.path.join(workspace_dir, ".venv")
        if not os.path.isdir(venv_dir):
            yield f"[scan] Creating venv at {venv_dir}"

        baseline = audit.run_baseline_audit(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
        )
        if baseline.error:
            yield f"[scan] FAILED: {baseline.error}"
            if baseline.error_stderr:
                yield f"[scan][stderr] {baseline.error_stderr}"
            return False

        if baseline.audit.returncode not in (None, 0):
            yield f"[scan] pip-audit exit code: {baseline.audit.returncode}"

        if not baseline.audit.ok or baseline.audit.audit_json is None:
            yield "[scan] FAILED: pip-audit produced no JSON output"
            for note in baseline.audit.stderr:
                if note:
                    yield f"[scan][stderr] {note}"
            return False

        for note in baseline.audit.stderr:
            if note:
                yield f"[scan][stderr] {note}"

        audit_ok, artifact_path = artifacts.write_audit_json(
            artifacts_dir=artifacts_dir,
            filename="pip_audit_before.json",
            content=baseline.audit.audit_json,
        )
        if not audit_ok:
            yield "[scan] FAILED: unable to write pip-audit artifact"
            return False
        yield f"[scan] Saved artifact: {artifact_path}"

        vuln_count = baseline.audit.vuln_count
        if vuln_count is None:
            yield "[scan] Vulnerability count unavailable (JSON parse failed)"
        else:
            yield f"[scan] Vulnerabilities found: {vuln_count}"
        return True

    def run_final_audit_stream(
        self,
        requirements_path: str,
        workspace_dir: str,
        artifacts_dir: str,
        before_audit_path: str,
    ) -> Generator[str, None, tuple[bool, Optional[int], Optional[int]]]:
        """Run a final pip-audit and write after/alias artifacts."""
        yield "[final] Starting final pip-audit"

        final = audit.run_final_audit(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
        )
        if final.venv_missing:
            yield "[final] FAILED: venv not found; cannot run final pip-audit"
            return False, None, None

        if final.audit.returncode not in (None, 0):
            yield f"[final][stderr] pip-audit exit code: {final.audit.returncode}"
        for note in final.audit.stderr:
            if note:
                yield f"[final][stderr] {note}"
        if not final.audit.ok or final.audit.audit_json is None:
            yield "[final] FAILED: pip-audit produced no JSON output"
            return False, None, None

        # Write the final audit payload and alias for downstream consumers.
        audit_ok, after_path = artifacts.write_audit_json(
            artifacts_dir=artifacts_dir,
            filename="pip_audit_after.json",
            content=final.audit.audit_json,
        )
        if not audit_ok:
            yield "[final] FAILED: unable to write after audit JSON"
            return False, None, None
        yield f"[final] Saved artifact: {after_path}"

        alias_path = os.path.join(artifacts_dir, "pip_audit.json")
        if not artifacts.write_audit_alias(after_path, alias_path):
            yield "[final] FAILED: unable to write pip_audit.json alias"
            return False, None, None
        yield f"[final] Saved alias: {alias_path}"

        before_raw = reporting.read_text_file(before_audit_path)
        before_count = audit.count_vulnerabilities(before_raw) if before_raw else None
        after_count = audit.count_vulnerabilities(final.audit.audit_json)
        # Surface counts for the UI even if JSON parsing fails.
        if before_count is None or after_count is None:
            yield "[final] Vulnerability counts unavailable (JSON parse failed)"
        else:
            yield f"[final] Vulnerabilities before: {before_count} | after: {after_count}"
        return True, before_count, after_count

    def _run_fixer_once(
        self,
        item: WorklistItem,
        entry: Optional[RequirementEntry],
        requirements_path: str,
        artifacts_dir: str,
        workspace_dir: str,
    ) -> tuple[Optional[str], str]:
        # Package up a single fix request with file paths and context.
        fix_version = item.fix_versions[0] if item.fix_versions else None
        patch_notes_name = f"PATCH_NOTES_{reporting.sanitize_filename(item.name)}.md"
        patch_notes_path = os.path.join(artifacts_dir, patch_notes_name)
        backup_path = os.path.join(os.path.dirname(requirements_path), "requirements_before.txt")
        task = FixerTask(
            package=item.name,
            current_spec=item.spec,
            vuln_ids=item.vuln_ids,
            fix_version=fix_version,
            requirements_path=requirements_path,
            requirements_before_path=backup_path,
            patch_notes_path=patch_notes_path,
            raw_line=entry.raw if entry else None,
            line_no=entry.line_no if entry else None,
        )
        # Delegate the task to a Fixer sub-agent so only FileEditorTool is used.
        conversation = Conversation(agent=self.agent, workspace=workspace_dir)
        fixer_prompt = task.prompt()
        coordinator_prompt = (
            "You are the Coordinator agent. Use DelegateTool to spawn a sub-agent "
            "with id 'fixer' using agent type 'fixer'. "
            "Delegate the following task to the fixer agent exactly.\n"
            "BEGIN FIXER PROMPT\n"
            f"{fixer_prompt}\n"
            "END FIXER PROMPT"
        )
        conversation.send_message(coordinator_prompt)
        conversation.run()

        patch_notes = reporting.read_text_file(patch_notes_path)
        if not patch_notes.strip():
            # Create fallback patch notes so verification can append results.
            reporting.write_fallback_patch_notes(
                item,
                requirements_path,
                backup_path,
                patch_notes_path,
            )
            patch_notes = reporting.read_text_file(patch_notes_path)
        return (patch_notes or None), patch_notes_path
