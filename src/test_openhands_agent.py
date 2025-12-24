#!/usr/bin/env python3
"""
Minimal OpenHands SDK test script (Task 2).
Creates a single agent that executes a simple terminal command.
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

    # Create agent with TerminalTool
    agent = Agent(
        llm=llm,
        tools=[
            Tool(name=TerminalTool.name),
        ],
    )

    # Create conversation in current directory
    cwd = os.getcwd()
    conversation = Conversation(agent=agent, workspace=cwd)

    # Send task to agent
    task = 'Execute the command: echo "Hello from OpenHands agent!"'
    print(f"\nTask: {task}\n")
    print("Agent output:")
    print("-" * 60)

    try:
        conversation.send_message(task)
        conversation.run()
        print("-" * 60)
        print("\n✓ Agent executed successfully!")

    except Exception as e:
        print(f"\n✗ Error running agent: {e}")
        raise


if __name__ == "__main__":
    main()
