import os

import gradio as gr

from src.agents.coordinator import Coordinator


def start_scan(repo_url: str):
    # Gradio streaming callback: yield incremental log output.
    log_lines = ["Preflight started..."]
    yield "\n".join(log_lines)

    try:
        # Coordinator owns the OpenHands agent and clone workflow.
        coordinator = Coordinator()
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
        yield "\n".join(log_lines)
        return

    # Run workspace directory on the host for now.
    workspace_root = os.path.join(os.getcwd(), "workspace")
    try:
        for line in coordinator.clone_repo_stream(repo_url, workspace_root=workspace_root):
            log_lines.append(line)
            yield "\n".join(log_lines)
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
        yield "\n".join(log_lines)


with gr.Blocks(title="PyCVE") as demo:
    gr.Markdown("# PyCVE")
    # Simple UI skeleton: repo input, run button, and live log output.
    repo_input = gr.Textbox(label="GitHub Repo URL", placeholder="https://github.com/owner/repo")
    run_button = gr.Button("Run Scan")
    log_output = gr.Textbox(label="Live Log Output", lines=12, interactive=False)
    run_button.click(start_scan, inputs=repo_input, outputs=log_output)


if __name__ == "__main__":
    demo.launch()
