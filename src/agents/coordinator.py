#!/usr/bin/env python3
import json
import os
import re
import shlex
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
from openhands.tools.terminal import TerminalTool


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
            ],
        )

    def clone_repo_stream(
        self,
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
        status = "success" if scan_ok else "failed"
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

    def parse_requirements_file(self, path: str) -> "RequirementsParseResult":
        """Read a requirements file and return parsed entries + directives."""
        # File wrapper for parse_requirements_text so callers can use a path.
        with open(path, "r", encoding="utf-8") as handle:
            return self.parse_requirements_text(handle.read())

    @staticmethod
    def parse_requirements_text(text: str) -> "RequirementsParseResult":
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
    ) -> Optional["RequirementEntry"]:
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
