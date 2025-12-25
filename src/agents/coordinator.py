#!/usr/bin/env python3
import os
import shlex
import threading
import time
import uuid
from typing import Generator, Optional

from dotenv import load_dotenv
from openhands.sdk import Agent, Conversation, LLM, Tool
from openhands.sdk.event import ObservationEvent
from openhands.tools.terminal import TerminalTool


class Coordinator:
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
    ) -> Generator[str, None, None]:
        # Stream a git clone to the caller while it runs in OpenHands.
        if not repo_url or not repo_url.strip():
            yield "[clone] FAILED: repo URL is required."
            return

        run_id = run_id or self._new_run_id()
        workspace_root = os.path.abspath(workspace_root)
        workspace_dir = os.path.join(workspace_root, run_id)
        repo_dir = os.path.join(workspace_dir, "repo")

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
            return

        if terminal_error:
            yield "[clone] FAILED: git clone reported an error."
            return

        if os.path.isdir(os.path.join(repo_dir, ".git")):
            yield f"[clone] SUCCESS: {repo_dir}"
        else:
            yield "[clone] FAILED: repo directory not found after clone."

    @staticmethod
    def _new_run_id() -> str:
        return f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _drain_events(
        conversation: Conversation,
        events_seen: int,
    ) -> tuple[int, bool, list[str]]:
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
        cleaned = text.replace("\r", "\n")
        return [line.rstrip("\n") for line in cleaned.splitlines() if line.strip()]
