import gradio as gr


def start_scan(repo_url: str) -> str:
    return "Preflight started..."


with gr.Blocks(title="PyCVE") as demo:
    gr.Markdown("# PyCVE")
    repo_input = gr.Textbox(label="GitHub Repo URL", placeholder="https://github.com/owner/repo")
    run_button = gr.Button("Run Scan")
    log_output = gr.Textbox(label="Live Log Output", lines=12, interactive=False)
    run_button.click(start_scan, inputs=repo_input, outputs=log_output)


if __name__ == "__main__":
    demo.launch()
