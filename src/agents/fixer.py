from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from openhands.sdk import Agent, Tool
from openhands.tools.delegate.registration import register_agent
from openhands.tools.file_editor import FileEditorTool


# Prevent duplicate registrations when Coordinator is constructed repeatedly.
_REGISTERED = False


def _display_list(items: list[str]) -> str:
    if not items:
        return "(none)"
    return ", ".join(items)


@dataclass
class FixerTask:
    package: str
    current_spec: str
    vuln_ids: list[str]
    fix_version: Optional[str]
    requirements_path: str
    requirements_before_path: str
    patch_notes_path: str
    raw_line: Optional[str] = None
    line_no: Optional[int] = None

    def prompt(self) -> str:
        # Build a deterministic instruction block for the Fixer agent.
        spec_display = self.current_spec or "(unpinned)"
        fix_display = self.fix_version or "(unknown)"
        fix_target = self.fix_version or "FIX_VERSION"
        line_display = self.raw_line or "(unknown line)"
        line_hint = f" (line {self.line_no})" if self.line_no else ""
        return (
            "You are the Fixer agent. Use FileEditorTool only.\n"
            "Context:\n"
            f"- package: {self.package}\n"
            f"- current spec: {spec_display}\n"
            f"- requirement line: {line_display}{line_hint}\n"
            f"- vulnerabilities: {_display_list(self.vuln_ids)}\n"
            f"- suggested fix version: {fix_display}\n"
            "Paths:\n"
            f"- requirements: {self.requirements_path}\n"
            f"- backup: {self.requirements_before_path}\n"
            f"- patch notes: {self.patch_notes_path}\n"
            "Steps:\n"
            "1) Read the requirements file.\n"
            "2) Before editing, write an exact copy to the backup path.\n"
            "3) If the fix version is unknown, do not edit requirements; write patch notes "
            "stating the package was skipped because no fix version was provided.\n"
            "4) Otherwise, update ONLY the requirement line for the package so the version "
            f"spec is >= {fix_target}. If it was unpinned, set it to "
            f"{self.package}>={fix_target}. Keep all other lines unchanged.\n"
            "5) Write patch notes with sections: Package, Vulnerabilities, Before, After, Notes. "
            "Include the exact before/after requirement line and note the backup creation.\n"
        )


def create_fixer_agent(agent_llm) -> Agent:
    # Restrict the Fixer agent to file edits only.
    return Agent(
        llm=agent_llm,
        tools=[
            Tool(name=FileEditorTool.name),
        ],
    )


def register_fixer_agent() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    # Register once so DelegateTool can spawn this agent by name.
    register_agent(
        name="fixer",
        factory_func=create_fixer_agent,
        description="Fixer agent that edits requirements.txt and writes patch notes.",
    )
    _REGISTERED = True
