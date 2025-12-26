import glob
import os
import re

import gradio as gr

from src.agents.coordinator import Coordinator


# CSS overrides for artifact file widgets: tighten spacing and highlight downloads.
ARTIFACT_CSS = """
/* Keep file row contents tight and left-aligned. */
.artifact-file .file-preview,
.artifact-file .file-preview-list .file-preview {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.6rem;
}

/* Limit width on desktop to reduce visual span. */
.artifact-file {
  width: 40%;
}

/* Expand to full width on smaller screens. */
@media (max-width: 900px) {
  .artifact-file {
    width: 100%;
  }
}

/* Make metadata and download controls easier to scan. */
.artifact-file .file-preview .file-size {
  margin-left: 0 !important;
  opacity: 0.75;
}

.artifact-file .file-preview a {
  margin-left: 0 !important;
  padding: 4px 10px;
  border-radius: 6px;
  background: #1f6feb;
  color: #fff !important;
  text-decoration: none;
  font-weight: 600;
}

.artifact-file .file-preview a:hover {
  background: #2b78ff;
}
"""


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


def _existing_artifact(artifacts_dir: str, filename: str):
    # Resolve an artifact path only when it exists so Gradio gets a valid file.
    if not artifacts_dir:
        return None
    # Avoid pointing Gradio at missing files to keep downloads stable.
    path = os.path.join(artifacts_dir, filename)
    return path if os.path.isfile(path) else None


def _collect_patch_notes(artifacts_dir: str, known_paths: list[str]) -> list[str]:
    # Merge known patch notes with any that were written after the coordinator cached paths.
    paths: list[str] = []
    seen: set[str] = set()
    for path in known_paths:
        if path and os.path.isfile(path) and path not in seen:
            paths.append(path)
            seen.add(path)
    if artifacts_dir:
        # Scan the artifacts folder for any additional patch notes created later.
        for path in glob.glob(os.path.join(artifacts_dir, "PATCH_NOTES_*.md")):
            if path and os.path.isfile(path) and path not in seen:
                paths.append(path)
                seen.add(path)
    return paths


def _collect_artifact_files(coordinator: Coordinator):
    # Gather current artifact file paths for download widgets in the UI.
    artifacts_dir = coordinator.latest_artifacts_dir
    summary_file = coordinator.latest_summary_path
    if not summary_file or not os.path.isfile(summary_file):
        # Fall back to the on-disk artifact if the cached summary is missing.
        summary_file = _existing_artifact(artifacts_dir, "SUMMARY.md")
    cve_file = _existing_artifact(artifacts_dir, "cve_status.json")
    before_file = _existing_artifact(artifacts_dir, "pip_audit_before.json")
    after_file = _existing_artifact(artifacts_dir, "pip_audit_after.json")
    patch_files = _collect_patch_notes(artifacts_dir, coordinator.patch_notes_paths)
    return summary_file, cve_file, before_file, after_file, patch_files


def start_scan(repo_url: str):
    # Gradio streaming callback: yield incremental log output.
    log_lines = ["Preflight started..."]
    table_rows: list[list[str]] = []
    # Keep the latest patch notes so the UI can show the most recent fix.
    patch_notes = ""
    summary_text = ""
    progress_text = "<div style=\"font-size: 18px;\">Fix progress: pending</div>"
    cve_summary = "CVE summary: pending"
    summary_file = None
    cve_file = None
    before_file = None
    after_file = None
    patch_files: list[str] = []
    # Emit the initial UI state before any long-running work starts.
    yield (
        "\n".join(log_lines),
        table_rows,
        patch_notes,
        progress_text,
        cve_summary,
        summary_text,
        summary_file,
        cve_file,
        before_file,
        after_file,
        patch_files,
    )

    try:
        # Coordinator owns the OpenHands agent and clone workflow.
        coordinator = Coordinator()
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
        # Surface initialization failures in the UI and stop streaming.
        yield (
            "\n".join(log_lines),
            table_rows,
            patch_notes,
            progress_text,
            cve_summary,
            summary_text,
            summary_file,
            cve_file,
            before_file,
            after_file,
            patch_files,
        )
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
            # Pull the latest CVE summary so the UI stays in sync with artifacts.
            cve_summary = coordinator.latest_cve_summary or cve_summary
            summary_text = coordinator.latest_summary or summary_text
            (
                summary_file,
                cve_file,
                before_file,
                after_file,
                patch_files,
            ) = _collect_artifact_files(coordinator)
            progress_match = re.match(r"^\[fix\] Progress: (\d+)/(\d+) \(([^)]+)\)$", line)
            if progress_match:
                current = int(progress_match.group(1))
                total = int(progress_match.group(2))
                package = progress_match.group(3)
                progress_text = _format_progress(current, total, package)
            if line.startswith("[run] COMPLETE:"):
                final_status = line
            # Stream the latest log/table/notes/progress state to Gradio.
            yield (
                "\n".join(log_lines),
                table_rows,
                patch_notes,
                progress_text,
                cve_summary,
                summary_text,
                summary_file,
                cve_file,
                before_file,
                after_file,
                patch_files,
            )
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
        yield (
            "\n".join(log_lines),
            table_rows,
            patch_notes,
            progress_text,
            cve_summary,
            summary_text,
            summary_file,
            cve_file,
            before_file,
            after_file,
            patch_files,
        )
    finally:
        if final_status:
            print(final_status)


with gr.Blocks(title="PyCVE", css=ARTIFACT_CSS) as demo:
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
    cve_summary = gr.Textbox(label="CVE Summary", lines=1, interactive=False)
    summary_output = gr.Textbox(label="Summary (Latest)", lines=12, interactive=False)
    # Downloadable artifacts produced by the scan workflow.
    summary_file = gr.File(label="SUMMARY.md", interactive=False, elem_classes=["artifact-file"])
    cve_file = gr.File(label="cve_status.json", interactive=False, elem_classes=["artifact-file"])
    before_file = gr.File(
        label="pip_audit_before.json",
        interactive=False,
        elem_classes=["artifact-file"],
    )
    after_file = gr.File(
        label="pip_audit_after.json",
        interactive=False,
        elem_classes=["artifact-file"],
    )
    patch_files = gr.File(
        label="PATCH_NOTES files",
        file_count="multiple",
        interactive=False,
        elem_classes=["artifact-file"],
    )
    run_button.click(
        start_scan,
        inputs=repo_input,
        outputs=[
            log_output,
            worklist_table,
            patch_notes,
            progress_output,
            cve_summary,
            summary_output,
            summary_file,
            cve_file,
            before_file,
            after_file,
            patch_files,
        ],
    )


if __name__ == "__main__":
    demo.launch()
