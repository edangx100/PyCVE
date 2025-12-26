import os
import re

import gradio as gr

from src.agents.coordinator import Coordinator


# Render a larger HTML progress bar for the UI.
def _format_progress(current: int, total: int, package: str) -> str:
    if total <= 0:
        return "<div style=\"font-size: 18px;\">Fix progress: unavailable</div>"
    # Keep a fixed-width bar so the layout stays stable across updates.
    width = 20
    filled = int(width * current / total)
    bar = "#" * filled + "-" * (width - filled)
    return (
        "<div style=\"font-size: 18px; font-family: monospace;\">"
        f"Fixing package {current}/{total}: {package}<br>"
        f"[{bar}]"
        "</div>"
    )


def start_scan(repo_url: str):
    # Gradio streaming callback: yield incremental log output.
    log_lines = ["Preflight started..."]
    table_rows: list[list[str]] = []
    # Keep the latest patch notes so the UI can show the most recent fix.
    patch_notes = ""
    progress_text = "<div style=\"font-size: 18px;\">Fix progress: pending</div>"
    yield "\n".join(log_lines), table_rows, patch_notes, progress_text

    try:
        # Coordinator owns the OpenHands agent and clone workflow.
        coordinator = Coordinator()
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
        yield "\n".join(log_lines), table_rows, patch_notes, progress_text
        return

    # Run workspace directory on the host for now.
    workspace_root = os.path.join(os.getcwd(), "workspace")
    artifacts_root = os.path.join(os.getcwd(), "artifacts")
    final_status = None
    try:
        for line in coordinator.clone_repo_stream(
            repo_url,
            workspace_root=workspace_root,
            artifacts_root=artifacts_root,
        ):
            log_lines.append(line)
            table_rows = coordinator.worklist_table_rows()
            # Mirror the coordinator's cached patch notes into the UI.
            patch_notes = coordinator.latest_patch_notes
            progress_match = re.match(r"^\[fix\] Progress: (\d+)/(\d+) \(([^)]+)\)$", line)
            if progress_match:
                current = int(progress_match.group(1))
                total = int(progress_match.group(2))
                package = progress_match.group(3)
                progress_text = _format_progress(current, total, package)
            if line.startswith("[run] COMPLETE:"):
                final_status = line
            yield "\n".join(log_lines), table_rows, patch_notes, progress_text
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
        yield "\n".join(log_lines), table_rows, patch_notes, progress_text
    finally:
        if final_status:
            print(final_status)


with gr.Blocks(title="PyCVE") as demo:
    gr.Markdown("# PyCVE")
    # Simple UI skeleton: repo input, run button, and live log output.
    repo_input = gr.Textbox(label="GitHub Repo URL", placeholder="https://github.com/owner/repo")
    run_button = gr.Button("Run Scan")
    log_output = gr.Textbox(label="Live Log Output", lines=12, interactive=False)
    worklist_table = gr.Dataframe(
        headers=["Package", "CVEs", "Current Version", "Suggested Fix"],
        label="Direct Dependency Worklist",
        interactive=False,
    )
    patch_notes = gr.Textbox(label="Patch Notes (Latest)", lines=12, interactive=False)
    progress_output = gr.HTML("<div style=\"font-size: 18px;\">Fix progress: pending</div>")
    run_button.click(
        start_scan,
        inputs=repo_input,
        outputs=[log_output, worklist_table, patch_notes, progress_output],
    )


if __name__ == "__main__":
    demo.launch()
