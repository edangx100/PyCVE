#!/usr/bin/env python3
"""
Minimal OpenHands SDK test script (Tasks 2-3).
Creates a single agent that executes a simple terminal command and delegates
one task to a sub-agent via DelegateTool.
"""

import os
from dotenv import load_dotenv

# Load environment variables FIRST, before importing OpenHands
load_dotenv()

# Set OpenRouter configuration in environment before SDK import
api_key = os.getenv("OPENROUTER_API_KEY")
if not api_key:
    print("Error: OPENROUTER_API_KEY not found in .env")
    exit(1)

# Ensure all OpenRouter environment variables are set BEFORE importing SDK
# LiteLLM requires OPENROUTER_API_KEY (confirmed by search results)
os.environ["OPENROUTER_API_KEY"] = api_key
# Also set the base URL as OPENAI_API_BASE (LiteLLM compatibility)
os.environ["OPENAI_API_BASE"] = "https://openrouter.ai/api/v1"
# OpenRouter-specific headers
os.environ["OR_SITE_URL"] = "http://localhost"
os.environ["OR_APP_NAME"] = "PyCVE OpenHands Test"

# NOW import OpenHands SDK after environment is configured
from openhands.sdk import LLM, Agent, Conversation, Tool
from openhands.sdk.conversation.response_utils import get_agent_final_response
from openhands.sdk.event import ObservationEvent
from openhands.tools.delegate import DelegateTool
from openhands.tools.delegate.registration import register_agent
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.task_tracker import TaskTrackerTool
from openhands.tools.terminal import TerminalTool


def main():
    # Get model from environment, default to minimax/minimax-m2.1
    model = os.getenv("COORDINATOR_OPENROUTER_MODEL", "openai/gpt-3.5-turbo")

    # Use openrouter/ prefix as shown in OpenRouter examples
    openrouter_model = f"openrouter/{model}"
    print(f"Initializing OpenHands agent with OpenRouter model: {openrouter_model}")
    print("=" * 60)

    # Configure LLM to use OpenRouter
    # Pass API key directly as shown in OpenRouter's LiteLLM example
    llm = LLM(
        model=openrouter_model,
        api_key=api_key,
    )

    def create_subprocess_agent(agent_llm):
        return Agent(
            llm=agent_llm,
            tools=[
                Tool(
                    name=TerminalTool.name,
                    params={"terminal_type": "subprocess"},
                ),
            ],
        )

    register_agent(
        name="subprocess",
        factory_func=create_subprocess_agent,
        description="Agent that uses subprocess terminal to avoid tmux",
    )

    # Create agent with TerminalTool and DelegateTool
    agent = Agent(
        llm=llm,
        tools=[
            Tool(
                name=TerminalTool.name,
                params={"terminal_type": "subprocess"},
            ),
            Tool(name=DelegateTool.name),
            Tool(name=FileEditorTool.name),
            Tool(name=TaskTrackerTool.name),
        ],
    )

    # Create conversation in current directory
    cwd = os.getcwd()
    conversation = Conversation(agent=agent, workspace=cwd)

    # Send task to agent
    test_file_path = os.path.join(cwd, "artifacts", "task3_file_editor_test.txt")
    task = (
        "First, run: echo \"Hello from OpenHands agent!\" using TerminalTool. "
        "Next, use FileEditorTool to create a file at "
        f"{test_file_path} with the exact content: \"FileEditorTool OK\". "
        "Then use TaskTrackerTool to view the current list, and plan a new list "
        "with a single task titled \"Verify built-in tools\" marked as done, "
        "with notes \"Task 3 built-in tools check\". "
        "Then use DelegateTool to spawn a sub-agent with id 'helper' using agent "
        "type 'subprocess', then delegate a task to run: "
        "echo \"Hello from OpenHands sub-agent!\" using TerminalTool. "
        "Return the sub-agent's output and a short tool summary."
    )
    print(f"\nTask: {task}\n")
    print("Agent output:")
    print("-" * 60)

    try:
        conversation.send_message(task)
        conversation.run()
        final_response = get_agent_final_response(conversation.state.events)
        if final_response:
            print("\nAgent final response:")
            print(final_response)

        tool_map = {
            "TerminalTool": TerminalTool.name,
            "DelegateTool": DelegateTool.name,
            "FileEditorTool": FileEditorTool.name,
            "TaskTrackerTool": TaskTrackerTool.name,
        }
        tool_results = {name: {"used": False, "error": False} for name in tool_map}
        for event in conversation.state.events:
            if isinstance(event, ObservationEvent):
                for display_name, tool_name in tool_map.items():
                    if event.tool_name == tool_name:
                        tool_results[display_name]["used"] = True
                        if event.observation.is_error:
                            tool_results[display_name]["error"] = True

        print("\nBuilt-in tools summary:")
        for display_name, result in tool_results.items():
            if not result["used"]:
                status = "NOT USED"
            elif result["error"]:
                status = "ERROR"
            else:
                status = "OK"
            print(f"- {display_name}: {status}")
        print("-" * 60)
        print("\n✓ Agent executed successfully!")

    except Exception as e:
        print(f"\n✗ Error running agent: {e}")
        raise


if __name__ == "__main__":
    main()
