"""Agent-server startup hooks for PyCVE Docker runs."""

from openhands.sdk import Agent, Tool
from openhands.tools.delegate import DelegateTool
from openhands.tools.delegate.registration import register_agent
from openhands.tools.file_editor import FileEditorTool


def _create_fixer_agent(agent_llm):
    # Restrict fixer agents to file edits only.
    return Agent(
        llm=agent_llm,
        tools=[Tool(name=FileEditorTool.name)],
    )


# Importing DelegateTool registers it with the tool registry for the server.
_ = DelegateTool

try:
    # Expose the Fixer agent type so DelegateTool can spawn it by name.
    register_agent(
        name="fixer",
        factory_func=_create_fixer_agent,
        description="Fixer agent that edits requirements.txt and writes patch notes.",
    )
except ValueError:
    # Ignore duplicate registration when the server reloads.
    pass
