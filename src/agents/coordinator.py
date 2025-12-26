#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
import venv
from dataclasses import dataclass, field
from typing import Generator, Optional

from dotenv import load_dotenv
from openhands.sdk import Agent, Conversation, LLM, Tool
from openhands.sdk.event import ObservationEvent
from openhands.tools.delegate import DelegateTool
from openhands.tools.terminal import TerminalTool

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
        if not repo_url or not repo_url.strip():
            yield "[clone] FAILED: repo URL is required."
            yield "[run] COMPLETE: failed"
            return

        run_id = run_id or self._new_run_id()
        workspace_root = os.path.abspath(workspace_root)
        workspace_dir = os.path.join(workspace_root, run_id)
        repo_dir = os.path.join(workspace_dir, "repo")
        self.latest_patch_notes = ""
        self.patch_notes_paths = []
        self.latest_cve_summary = "CVE summary: pending"

        # Each run gets an isolated workspace to keep artifacts and venvs separate.
        os.makedirs(workspace_dir, exist_ok=True)

        yield f"[clone] Run ID: {run_id}"
        yield f"[clone] Workspace: {workspace_dir}"
        yield f"[clone] Repo URL: {repo_url}"

        # Ask the agent to run the clone command in the workspace directory.
        conversation = Conversation(agent=self.agent, workspace=workspace_dir)
        safe_url = shlex.quote(repo_url)
        clone_cmd = f"git clone --progress {safe_url} repo"
        task = (
            "You are the Coordinator agent. Use TerminalTool to clone the repo. "
            f"Run exactly this command: {clone_cmd}. "
            "Return a short success or failure message once the clone completes."
        )

        conversation.send_message(task)

        run_errors = []
        terminal_error = False

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
            yield "[run] COMPLETE: failed"
            return

        if terminal_error:
            yield "[clone] FAILED: git clone reported an error."
            yield "[run] COMPLETE: failed"
            return

        if os.path.isdir(os.path.join(repo_dir, ".git")):
            yield f"[clone] SUCCESS: {repo_dir}"
        else:
            yield "[clone] FAILED: repo directory not found after clone."
            yield "[run] COMPLETE: failed"
            return

        # Parse requirements.txt and gate on directives before later stages.
        requirements_path = os.path.join(repo_dir, "requirements.txt")
        if not os.path.isfile(requirements_path):
            yield f"[parse] SKIPPED: requirements.txt not found at {requirements_path}"
            yield "[run] COMPLETE: skipped"
            return

        yield f"[parse] Found requirements.txt at {requirements_path}"
        parse_result = self.parse_requirements_file(requirements_path)
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
            yield "[run] COMPLETE: skipped"
            return

        # Persist audit artifacts under a run-scoped directory.
        artifacts_root = artifacts_root or os.path.join(os.getcwd(), "artifacts")
        artifacts_root = os.path.abspath(artifacts_root)
        os.makedirs(artifacts_root, exist_ok=True)
        artifacts_dir = os.path.join(artifacts_root, run_id)
        os.makedirs(artifacts_dir, exist_ok=True)
        yield f"[artifacts] Directory: {artifacts_dir}"

        scan_ok = yield from self.run_pip_audit_stream(
            requirements_path=requirements_path,
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
        )
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
                    self._normalize_name(entry.name): entry for entry in parse_result.editable
                }
                total = len(worklist)
                yield f"[fix] Starting fix loop: {total} package(s)"
                for index, target in enumerate(worklist, start=1):
                    entry = entry_map.get(self._normalize_name(target.name))
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
                        status, before_count, after_count, reverted = self._spot_check_fix(
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
                        self.latest_patch_notes = self._read_text_file(patch_path)
                        yield f"[fix] Patch notes saved: {patch_path}"
                    else:
                        self.latest_patch_notes = ""
                        yield "[fix] Patch notes not generated"
            # After all fixes, run a final audit and write the "after" artifacts.
            final_ok, _, _ = yield from self.run_final_audit_stream(
                requirements_path=requirements_path,
                workspace_dir=workspace_dir,
                artifacts_dir=artifacts_dir,
                before_audit_path=audit_path,
            )
            if final_ok:
                # Build cve_status.json and surface fixed/remaining counts to the UI.
                cve_path = os.path.join(artifacts_dir, "cve_status.json")
                cve_ok, fixed_count, remaining_count = self.write_cve_status(
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
        else:
            # Clear any previous worklist if the scan failed.
            self.latest_worklist = []
        status = "success" if scan_ok and final_ok else "failed"
        yield f"[run] COMPLETE: {status}"

    @staticmethod
    def _new_run_id() -> str:
        return f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

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

    def parse_requirements_file(self, path: str) -> RequirementsParseResult:
        """Read a requirements file and return parsed entries + directives."""
        # File wrapper for parse_requirements_text so callers can use a path.
        with open(path, "r", encoding="utf-8") as handle:
            return self.parse_requirements_text(handle.read())

    @staticmethod
    def parse_requirements_text(text: str) -> RequirementsParseResult:
        """Parse editable requirements, flag directives, and keep unknown lines."""
        # Conservative parser: editable specs only, directive/unknown are gated.
        result = RequirementsParseResult()
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            cleaned = Coordinator._strip_inline_comment(raw_line)
            if not cleaned.strip():
                continue

            stripped = cleaned.strip()
            if Coordinator._is_directive(stripped):
                result.directives.append(DirectiveEntry(line_no=line_no, raw=stripped))
                continue

            parsed = Coordinator._parse_editable_requirement(stripped, line_no)
            if parsed:
                result.editable.append(parsed)
            else:
                result.unknown.append(DirectiveEntry(line_no=line_no, raw=stripped))

        if result.directives:
            result.skip_reason = "directive or unsupported install option detected"

        return result

    @staticmethod
    def _strip_inline_comment(line: str) -> str:
        """Remove inline comments while preserving requirement tokens."""
        # Remove inline comments while preserving trailing whitespace in specs.
        if "#" not in line:
            return line
        if line.lstrip().startswith("#"):
            return ""
        parts = re.split(r"\s+#", line, maxsplit=1)
        return parts[0].rstrip()

    @staticmethod
    def _is_directive(line: str) -> bool:
        """Detect lines that imply a non-standard requirement source."""
        # Flag any directive/include/index/URL/path as skip-worthy.
        lower = line.lower()
        if lower.startswith("-"):
            return True
        if lower.startswith(("git+", "hg+", "svn+", "bzr+")):
            return True
        if "://" in line:
            return True
        if line.startswith((".", "/", "~")):
            return True
        if lower.startswith("file:"):
            return True
        if "@" in line:
            return True
        return False

    @staticmethod
    def _parse_editable_requirement(
        line: str,
        line_no: int,
    ) -> Optional[RequirementEntry]:
        """Parse simple PEP 440 name + optional version constraints."""
        # Accept only simple name[op]version constraints with comma-separated ops.
        name_re = r"[A-Za-z0-9][A-Za-z0-9._-]*"
        op_re = r"(==|>=|<=|~=|!=|>|<)"
        version_re = r"[A-Za-z0-9][A-Za-z0-9._-]*"
        spec_re = rf"{op_re}\s*{version_re}"
        combined_re = rf"^(?P<name>{name_re})(?P<spec>\s*(?:{spec_re})(?:\s*,\s*{spec_re})*)?\s*$"
        match = re.match(combined_re, line)
        if not match:
            return None
        name = match.group("name")
        spec = match.group("spec") or ""
        return RequirementEntry(name=name, spec=spec.strip(), line_no=line_no, raw=line)

    @staticmethod
    def _venv_python(venv_dir: str) -> str:
        """Return the venv interpreter path for the current platform."""
        # checks whether the current platform is Windows
        if os.name == "nt":
            return os.path.join(venv_dir, "Scripts", "python.exe")
        # else POSIX systems 
        return os.path.join(venv_dir, "bin", "python")

    @staticmethod
    def _run_command(args: list[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess[str]:
        """Run a subprocess and always capture stdout/stderr."""
        # Keep output for later error reporting without raising exceptions.
        return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)

    def _ensure_venv(self, venv_dir: str) -> None:
        """Create a venv with pip if it doesn't exist yet."""
        # Avoid touching an existing environment (reuse if present).
        if os.path.isdir(venv_dir):
            return
        # Build a minimal venv that includes pip for installs.
        builder = venv.EnvBuilder(with_pip=True)
        builder.create(venv_dir)

    @staticmethod
    def _count_vulnerabilities(raw_json: str) -> Optional[int]:
        """Best-effort count of vulnerabilities from pip-audit JSON output."""
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError:
            return None

        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            if isinstance(payload.get("dependencies"), list):
                items = payload["dependencies"]
            elif isinstance(payload.get("results"), list):
                items = payload["results"]
            else:
                items = [payload]
        else:
            return None

        total = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            vulns = item.get("vulns")
            if vulns is None:
                vulns = item.get("vulnerabilities")
            if isinstance(vulns, list):
                total += len(vulns)
        return total

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize package names for reliable comparisons."""
        # PEP 503 normalization: lowercase and replace runs of -_. with a single dash.
        return re.sub(r"[-_.]+", "-", name).lower()

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        """Make a safe filename segment from a package name."""
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
        return cleaned or "package"

    @staticmethod
    def _extract_audit_items(payload: object) -> list[dict]:
        """Return a list of dependency dicts from pip-audit JSON output."""
        # pip-audit may return a list or wrap dependencies in a dict; normalize to list[dict].
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("dependencies", "results"):
                if isinstance(payload.get(key), list):
                    return [item for item in payload[key] if isinstance(item, dict)]
            return [payload]
        return []

    @staticmethod
    def _string_list(values: object) -> list[str]:
        """Normalize an input into a list of strings."""
        # Accept both singular strings and string lists; ignore other shapes.
        if isinstance(values, list):
            return [str(value) for value in values if value]
        if isinstance(values, str):
            return [values]
        return []

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
            self._normalize_name(entry.name): entry for entry in parse_result.editable
        }
        worklist: list[WorklistItem] = []
        seen: set[str] = set()

        for item in self._extract_audit_items(payload):
            name = item.get("name") or item.get("package") or item.get("dependency")
            if not name:
                continue
            normalized = self._normalize_name(str(name))
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
                for alias in self._string_list(vuln.get("aliases")):
                    vuln_ids.append(alias)
                fixes = vuln.get("fix_versions")
                if fixes is None:
                    fixes = vuln.get("fixed_versions")
                for fix in self._string_list(fixes):
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
                    vuln_ids=self._unique_strings(vuln_ids),
                    fix_versions=self._unique_strings(fix_versions),
                    is_editable=True,
                    skip_reason=None,
                )
            )
            seen.add(normalized)

        return worklist

    @staticmethod
    def _unique_strings(items: list[str]) -> list[str]:
        """Return a stable, de-duplicated list of strings."""
        # Preserve original ordering while dropping repeats.
        seen: set[str] = set()
        unique: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

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
        try:
            self._ensure_venv(venv_dir)
        except Exception as exc:
            yield f"[scan] FAILED: unable to create venv: {exc}"
            return False

        venv_python = self._venv_python(venv_dir)
        install_cmd = [
            venv_python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "pip-audit",
        ]
        install_result = self._run_command(install_cmd, cwd=workspace_dir)
        if install_result.returncode != 0:
            yield f"[scan] FAILED: pip-audit install returned {install_result.returncode}"
            if install_result.stderr.strip():
                yield f"[scan][stderr] {install_result.stderr.strip()}"
            return False

        audit_cmd = [
            venv_python,
            "-m",
            "pip_audit",
            "-r",
            requirements_path,
            "--format",
            "json",
        ]
        audit_result = self._run_command(audit_cmd, cwd=os.path.dirname(requirements_path))
        if audit_result.returncode != 0:
            yield f"[scan] pip-audit exit code: {audit_result.returncode}"

        if not audit_result.stdout.strip():
            yield "[scan] FAILED: pip-audit produced no JSON output"
            if audit_result.stderr.strip():
                yield f"[scan][stderr] {audit_result.stderr.strip()}"
            return False

        artifact_path = os.path.join(artifacts_dir, "pip_audit_before.json")
        with open(artifact_path, "w", encoding="utf-8") as handle:
            handle.write(audit_result.stdout)
        yield f"[scan] Saved artifact: {artifact_path}"

        vuln_count = self._count_vulnerabilities(audit_result.stdout)
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

        # Reuse the existing venv from the baseline scan to avoid reinstalling tools.
        venv_dir = os.path.join(workspace_dir, ".venv")
        if not os.path.isdir(venv_dir):
            yield "[final] FAILED: venv not found; cannot run final pip-audit"
            return False, None, None

        # Run pip-audit and surface any stderr notes in the live log.
        audit_json, audit_notes = self._run_pip_audit_json(venv_dir, requirements_path)
        if audit_notes:
            for note in audit_notes:
                if note:
                    yield f"[final][stderr] {note}"
        if audit_json is None:
            yield "[final] FAILED: pip-audit produced no JSON output"
            return False, None, None

        # Write the final audit output as pip_audit_after.json.
        after_path = os.path.join(artifacts_dir, "pip_audit_after.json")
        try:
            with open(after_path, "w", encoding="utf-8") as handle:
                handle.write(audit_json)
            yield f"[final] Saved artifact: {after_path}"
        except OSError as exc:
            yield f"[final] FAILED: unable to write after audit JSON: {exc}"
            return False, None, None

        # Mirror the final output to pip_audit.json for downstream consumers.
        alias_path = os.path.join(artifacts_dir, "pip_audit.json")
        try:
            shutil.copyfile(after_path, alias_path)
            yield f"[final] Saved alias: {alias_path}"
        except OSError as exc:
            yield f"[final] FAILED: unable to write pip_audit.json alias: {exc}"
            return False, None, None

        # Compare before/after vulnerability counts for UI reporting.
        before_raw = self._read_text_file(before_audit_path)
        before_count = self._count_vulnerabilities(before_raw) if before_raw else None
        after_count = self._count_vulnerabilities(audit_json)
        if before_count is None or after_count is None:
            yield "[final] Vulnerability counts unavailable (JSON parse failed)"
        else:
            yield f"[final] Vulnerabilities before: {before_count} | after: {after_count}"
        return True, before_count, after_count

    @staticmethod
    def _read_text_file(path: str) -> str:
        """Read a text file, returning empty string on failure."""
        # Small helper so UI logging can reuse file contents without raising.
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError:
            return ""

    @staticmethod
    def _read_json_file(path: str) -> Optional[object]:
        """Read JSON from disk, returning None on failure."""
        # Best-effort loader for baseline/spot-check artifacts.
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _files_differ(path_a: str, path_b: str) -> Optional[bool]:
        """Return True if file contents differ, False if same, None if unreadable."""
        # Avoid spot-check work if the fixer did not change requirements.txt.
        try:
            with open(path_a, "r", encoding="utf-8") as handle:
                content_a = handle.read()
            with open(path_b, "r", encoding="utf-8") as handle:
                content_b = handle.read()
        except OSError:
            return None
        return content_a != content_b

    def _find_requirement_line(self, path: str, package_name: str) -> Optional[str]:
        """Return the raw requirement line for a package from the given file."""
        normalized_target = self._normalize_name(package_name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line_no, raw_line in enumerate(handle, start=1):
                    # Skip blank/comment lines and parse only simple editable requirements.
                    cleaned = self._strip_inline_comment(raw_line)
                    if not cleaned.strip():
                        continue
                    parsed = self._parse_editable_requirement(cleaned.strip(), line_no)
                    if not parsed:
                        continue
                    # Match on normalized name so casing and separators do not matter.
                    if self._normalize_name(parsed.name) == normalized_target:
                        return raw_line.strip()
        except OSError:
            return None
        return None

    def write_cve_status(
        self,
        before_audit_path: str,
        after_audit_path: str,
        artifacts_dir: str,
    ) -> tuple[bool, Optional[int], Optional[int]]:
        """Write cve_status.json and return fixed/remaining counts."""
        # Load both audits so we can diff vulnerability records across runs.
        before_payload = self._read_json_file(before_audit_path)
        after_payload = self._read_json_file(after_audit_path)
        if before_payload is None or after_payload is None:
            return False, None, None

        status_payload, fixed_count, remaining_count = self._build_cve_status_payload(
            before_payload, after_payload
        )
        cve_path = os.path.join(artifacts_dir, "cve_status.json")
        try:
            # Persist a stable, human-readable artifact for downstream tooling.
            with open(cve_path, "w", encoding="utf-8") as handle:
                json.dump(status_payload, handle, indent=2)
        except OSError:
            return False, None, None
        return True, fixed_count, remaining_count

    def _build_cve_status_payload(
        self,
        before_payload: object,
        after_payload: object,
    ) -> tuple[dict[str, list[dict[str, object]]], int, int]:
        """Build the before/after/fixed/remaining structure for cve_status.json."""
        before_records = self._collect_vuln_records(before_payload)
        after_records = self._collect_vuln_records(after_payload)

        # Compare records by (package, advisory_id) so we can diff across runs.
        after_keys = {self._vuln_record_key(record) for record in after_records}

        fixed_records: list[dict[str, object]] = []
        for record in before_records:
            # If a before record no longer appears after, mark it as fixed.
            if self._vuln_record_key(record) in after_keys:
                continue
            fixed_entry = dict(record)
            fixed_entry["status"] = "fixed"
            fixed_records.append(fixed_entry)

        remaining_records: list[dict[str, object]] = []
        for record in after_records:
            # Everything still present after the fix loop is considered remaining.
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

    def _collect_vuln_records(self, payload: object) -> list[dict[str, object]]:
        """Extract vulnerability records from pip-audit JSON output."""
        records: list[dict[str, object]] = []
        seen: set[tuple[str, str]] = set()

        for item in self._extract_audit_items(payload):
            # Normalize package names and vuln fields across pip-audit output variants.
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
                # Prefer advisory IDs, then fall back to aliases when needed.
                advisory_id = vuln.get("id") or vuln.get("cve") or vuln.get("name")
                advisory_id = str(advisory_id).strip() if advisory_id else ""
                aliases = self._unique_strings(self._string_list(vuln.get("aliases")))
                fix_versions = self._string_list(
                    vuln.get("fix_versions") or vuln.get("fixed_versions")
                )
                fix_versions = self._unique_strings(fix_versions)

                if not advisory_id and aliases:
                    advisory_id = aliases[0]
                if not advisory_id:
                    advisory_id = "unknown"

                cve_ids = [
                    alias for alias in aliases if str(alias).upper().startswith("CVE-")
                ]
                if advisory_id.upper().startswith("CVE-"):
                    cve_ids = self._unique_strings([advisory_id] + cve_ids)
                else:
                    cve_ids = self._unique_strings(cve_ids)

                # Capture a compact per-vuln record for before/after diffs.
                record = {
                    "package": package,
                    "advisory_id": advisory_id,
                    "cve_ids": cve_ids,
                }
                if aliases:
                    record["aliases"] = aliases
                if fix_versions:
                    record["fix_versions"] = fix_versions

                # Drop duplicates so each advisory is reported once per package.
                key = self._vuln_record_key(record)
                if key in seen:
                    continue
                seen.add(key)
                records.append(record)

        return records

    def _vuln_record_key(self, record: dict[str, object]) -> tuple[str, str]:
        """Build a stable key for comparing vulnerability records."""
        # Use normalized package + advisory ID to avoid casing/alias drift.
        package = str(record.get("package") or "")
        advisory_id = str(record.get("advisory_id") or "")
        return self._normalize_name(package), advisory_id

    def _write_fallback_patch_notes(
        self,
        item: WorklistItem,
        requirements_path: str,
        backup_path: str,
        patch_notes_path: str,
    ) -> None:
        """Write minimal patch notes if the Fixer agent failed to create them."""
        # Derive before/after lines from the backup and current requirements.
        before_line = self._find_requirement_line(backup_path, item.name)
        after_line = self._find_requirement_line(requirements_path, item.name)
        vuln_block = ", ".join(item.vuln_ids) if item.vuln_ids else "(none)"
        # Build a lightweight note so verification can still append results.
        notes = [
            f"# Package: {item.name}",
            "",
            "## Vulnerabilities",
            vuln_block,
            "",
            "## Before",
            before_line or "(unknown)",
            "",
            "## After",
            after_line or "(unknown)",
            "",
            "## Notes",
            (
                "Coordinator generated patch notes because the Fixer agent did not write them."
            ),
        ]
        if os.path.isfile(backup_path):
            notes.append(f"Backup created at {backup_path}")
        try:
            with open(patch_notes_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(notes))
                handle.write("\n")
        except OSError:
            return

    def _run_pip_audit_json(
        self,
        venv_dir: str,
        requirements_path: str,
    ) -> tuple[Optional[str], list[str]]:
        """Run pip-audit and return JSON output + any stderr notes."""
        # Reuse the existing venv so spot-checks stay fast and isolated.
        venv_python = self._venv_python(venv_dir)
        audit_cmd = [
            venv_python,
            "-m",
            "pip_audit",
            "-r",
            requirements_path,
            "--format",
            "json",
        ]
        audit_result = self._run_command(audit_cmd, cwd=os.path.dirname(requirements_path))
        notes: list[str] = []
        if audit_result.returncode != 0:
            notes.append(f"pip-audit exit code: {audit_result.returncode}")
        if audit_result.stderr.strip():
            notes.append(audit_result.stderr.strip())
        if not audit_result.stdout.strip():
            return None, notes
        return audit_result.stdout, notes

    def _count_package_vulns(self, payload: object, package_name: str) -> Optional[int]:
        """Count vulnerabilities for a specific package name."""
        # Compare only the target package so other dependency changes do not skew results.
        normalized_target = self._normalize_name(package_name)
        items = self._extract_audit_items(payload)
        if not items:
            return None
        total = 0
        found = False
        for item in items:
            name = item.get("name") or item.get("package") or item.get("dependency")
            if not name:
                continue
            if self._normalize_name(str(name)) != normalized_target:
                continue
            found = True
            vulns = item.get("vulns")
            if vulns is None:
                vulns = item.get("vulnerabilities")
            if isinstance(vulns, list):
                total += len(vulns)
        if not found:
            return 0
        return total

    @staticmethod
    def _revert_requirements(backup_path: str, requirements_path: str) -> bool:
        """Restore requirements.txt from the backup file."""
        # Roll back a change if the spot-check indicates regressions.
        if not os.path.isfile(backup_path):
            return False
        try:
            shutil.copyfile(backup_path, requirements_path)
        except OSError:
            return False
        return True

    def _append_verification_notes(
        self,
        patch_notes_path: str,
        status: str,
        before_count: Optional[int],
        after_count: Optional[int],
        reverted: bool,
        notes: list[str],
    ) -> None:
        """Append verification results to the patch notes file."""
        # Keep fixer notes intact and append a verification section.
        before_display = "unknown" if before_count is None else str(before_count)
        after_display = "unknown" if after_count is None else str(after_count)
        extra_notes = "; ".join(note for note in notes if note)
        lines = [
            "",
            "Verification",
            f"- status: {status}",
            f"- before: {before_display}",
            f"- after: {after_display}",
            f"- reverted: {'yes' if reverted else 'no'}",
        ]
        if extra_notes:
            lines.append(f"- notes: {extra_notes}")
        try:
            with open(patch_notes_path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines))
                handle.write("\n")
        except OSError:
            return

    def _spot_check_fix(
        self,
        package_name: str,
        requirements_path: str,
        backup_path: str,
        artifacts_dir: str,
        workspace_dir: str,
        patch_notes_path: str,
        before_audit_path: str,
    ) -> tuple[str, Optional[int], Optional[int], bool]:
        """Re-run pip-audit and compare vulnerabilities for a single package."""
        status = "verified: failed"
        before_count: Optional[int] = None
        after_count: Optional[int] = None
        reverted = False
        notes: list[str] = []

        changed = self._files_differ(backup_path, requirements_path)
        if changed is False:
            # No change means nothing to verify.
            notes.append("no edit applied; spot-check skipped")
            self._append_verification_notes(
                patch_notes_path,
                status,
                before_count,
                after_count,
                reverted,
                notes,
            )
            return status, before_count, after_count, reverted

        before_payload = self._read_json_file(before_audit_path)
        if before_payload is None:
            # Proceed even if baseline is missing, but note the gap.
            notes.append("baseline audit missing or unreadable")
        else:
            before_count = self._count_package_vulns(before_payload, package_name)

        venv_dir = os.path.join(workspace_dir, ".venv")
        # Run a new audit against the edited requirements.
        audit_json, audit_notes = self._run_pip_audit_json(venv_dir, requirements_path)
        if audit_notes:
            notes.append("; ".join(audit_notes))
        if audit_json is None:
            notes.append("pip-audit spot-check failed")
            self._append_verification_notes(
                patch_notes_path,
                status,
                before_count,
                after_count,
                reverted,
                notes,
            )
            return status, before_count, after_count, reverted

        # Persist spot-check output for debugging and later review.
        spotcheck_name = f"pip_audit_spotcheck_{self._sanitize_filename(package_name)}.json"
        spotcheck_path = os.path.join(artifacts_dir, spotcheck_name)
        try:
            with open(spotcheck_path, "w", encoding="utf-8") as handle:
                handle.write(audit_json)
        except OSError:
            notes.append("unable to save spot-check audit artifact")

        try:
            after_payload = json.loads(audit_json)
        except json.JSONDecodeError:
            after_payload = None
            notes.append("spot-check JSON parse failed")

        if after_payload is not None:
            after_count = self._count_package_vulns(after_payload, package_name)

        if before_count is None or after_count is None:
            notes.append("unable to compare vulnerability counts")
        else:
            # Decide success/failure based on the package-specific counts.
            if after_count < before_count:
                status = "verified: vuln removed"
            elif after_count > before_count:
                notes.append("vulnerability count increased")
                reverted = self._revert_requirements(backup_path, requirements_path)
                if reverted:
                    notes.append("requirements.txt reverted to backup")
                else:
                    notes.append("failed to revert requirements.txt")
            else:
                notes.append("vulnerability count unchanged")

        self._append_verification_notes(
            patch_notes_path,
            status,
            before_count,
            after_count,
            reverted,
            notes,
        )
        return status, before_count, after_count, reverted

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
        patch_notes_name = f"PATCH_NOTES_{self._sanitize_filename(item.name)}.md"
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

        patch_notes = self._read_text_file(patch_notes_path)
        if not patch_notes.strip():
            # Create fallback patch notes so verification can append results.
            self._write_fallback_patch_notes(
                item,
                requirements_path,
                backup_path,
                patch_notes_path,
            )
            patch_notes = self._read_text_file(patch_notes_path)
        return (patch_notes or None), patch_notes_path


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
