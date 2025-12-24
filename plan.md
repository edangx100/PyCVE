# PyCVE Agents 

A **two-agent** OpenHands SDK demo that scans a user-supplied GitHub repo for Python dependency vulnerabilities (via `requirements.txt`) and applies **safe, direct-dependency-only** patches, with **optional OSV enrichment via MCP**.

The Coordinator runs `pip-audit` directly; the Fixer focuses on safe edits + per-package verification + patch notes.

---

## 🎯 Demo Goal

Given a **GitHub repo URL** in a Gradio UI, the system will:

1. Clone the repo
2. If `requirements.txt` exists and is simple enough to parse → run baseline vulnerability scan
3. Build a **worklist of vulnerable direct dependencies**
4. Delegate fixes **one package at a time** to a Fixer agent (safe edits only)
5. Verify by re-running `pip-audit` (baseline vs final)
6. Produce clean, auditable artifacts (before/after audit, summary, per-package patch notes)
7. Optionally enrich findings via **OSV MCP** (best-effort, never blocking)

---

## 🧩 Technology Stack

### Agent Framework

* **OpenHands Software Agent SDK**

  * lifecycle, tool calling, delegation, MCP integration
  * reference: `https://docs.openhands.dev/sdk`
* No OpenHands hosted app UI (SDK-only).

### UI Layer

* **Gradio**

  * repo URL input, run button
  * streamed progress (stage + live log)
  * artifact download links

### Language Model

* **minimax/minimax-m2.1** via **OpenRouter**

  * Used by **Coordinator** and **Fixer**
  * OpenHands OpenRouter docs: `https://docs.openhands.dev/openhands/usage/llms/openrouter`

`.env`:

* `OPENROUTER_API_KEY`
* `COORDINATOR_OPENROUTER_MODEL` (default: `minimax/minimax-m2.1`)
* `FIXER_OPENROUTER_MODEL` (default: `minimax/minimax-m2.1`)

Example OpenHands LLM config:

```yaml
llms:
  openrouter_coordinator:
    platform: openrouter
    api_key_env: OPENROUTER_API_KEY
    model: ${COORDINATOR_OPENROUTER_MODEL}

  openrouter_fixer:
    platform: openrouter
    api_key_env: OPENROUTER_API_KEY
    model: ${FIXER_OPENROUTER_MODEL}
```

### MCP Server (OSV Enrichment)

* **EdenYavin/OSV-MCP (stdio)**

  * run as a local MCP server via `uv`
* OpenHands MCP guide: `https://docs.openhands.dev/sdk/guides/mcp`

`.env`:

* `OSV_MCP_DIR` (path to OSV-MCP checkout)
* `OSV_MCP_ENABLED` (default: `true`)

---

## ✅ Scope (MVP)

### In scope

* **Only** dependencies in `requirements.txt`
* Scan via **pip-audit** (JSON output)
* Fix policy: **direct dependencies only**
* Safe editability gating:

  * editable: `pkg`, `pkg==x.y.z`, `pkg>=x.y.z`, `pkg~=x.y.z`
  * non-editable: anything else (URLs, VCS, local paths, `-e`, constraints/includes, etc.)
* Required verification:

  * baseline `pip-audit` (before)
  * final `pip-audit` (after)
  * per-package “spot-check” audit after an edit (Fixer decision-making)
* MCP enrichment:

  * best-effort advisory context (never blocks scan/fix/verify)

### Out of scope

* poetry / pip-tools / lockfiles
* transitive dependency fixing
* test/CI integration
* private indexes

---

## 🏗️ High-Level Architecture (2 Agents)

```text
+--------------------------------------------------------------+
|                       Gradio Web UI                          |
|  Input: GitHub repo URL                                      |
|  Output: streamed stage + live log + artifacts download      |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                 Coordinator Agent (main)                     |
|  - preflight (run_id, Docker workspace, MCP init)            |
|  - clone repo                                                |
|  - parse requirements.txt (directive gating)                 |
|  - run baseline pip-audit (writes before artifact)           |
|  - build direct-dep worklist from findings                   |
|  - delegate Fixer per package (serialized)                   |
|  - run final pip-audit (writes after + alias)                |
|  - write SUMMARY + cve_status + links to patch notes         |
+------------------------------+-------------------------------+
                               |
                               | DelegateTool (per package)
                               v
+--------------------------------------------------------------+
|                       Fixer Agent                            |
|  - receives one package work item at a time                  |
|  - safe edit requirements.txt                                |
|  - best-effort install (optional but recommended)            |
|  - spot-check pip-audit for that package                     |
|  - write PATCH_NOTES_<pkg>.md                                |
|  - optional OSV MCP enrichment for patch notes               |
+--------------------------------------------------------------+
```

---

## 🔌 Built-in OpenHands Tools (required)

* `DelegateTool`
* `TerminalTool`
* `FileEditorTool`
* `TaskTrackerTool`

---



---

## 🔒 MCP Tool Filtering Policy (OSV-only)

### Goal

Allow MCP tools **only** from OSV-MCP, without risking removal of required OpenHands built-ins.  

OpenHands SDK reference: [MCP Integration](https://docs.openhands.dev/sdk/arch/tool-system#mcp-integration)

### Configuration

```python
mcp_config = {
  "mcpServers": {
    "osv": {
      "command": "uv",
      "args": ["--directory", os.environ["OSV_MCP_DIR"], "run", "osv-server"],
      "env": {}
    }
  }
}

# Primary intent: only OSV MCP tools visible
filter_tools_regex = r"^(osv|OSV|osv_).*"
```

### Safe fallback (if regex unexpectedly affects built-ins)

```python
filter_tools_regex = (
  r"^(DelegateTool|TerminalTool|FileEditorTool|TaskTrackerTool"
  r"|osv|OSV|osv_).*"
)
```

### Preflight operational check

* Log tool counts / names (at least categories)
* If built-ins missing → **FAIL FAST**
* If OSV MCP tools missing → mark MCP as unavailable and continue (best-effort)

---

## 📁 Workspace & Environment Strategy

### Sandboxing Options

**Docker Sandbox** is the recommended workspace strategy for production use.

OpenHands SDK Docker reference: `https://docs.openhands.dev/sdk/guides/agent-server/docker-sandbox`

---

### Docker Sandbox Implementation

**Why Docker?**

* **Security**: Cloning arbitrary GitHub repos and installing their dependencies is risky
* **Isolation**: Each run gets a fresh container; no contamination between runs
* **Reproducibility**: Consistent Python/pip/pip-audit versions across environments
* **Safety**: Malicious packages can't affect host system

**Implementation**

Use `DockerWorkspace` to set up the containerized environment:

```python
from openhands_sdk import DockerWorkspace

workspace = DockerWorkspace(
    base_container_image="python:3.11-slim",  # or custom image
    workspace_mount_path="/workspace",
    extra_ports=False,  # set True for VS Code Web access (debugging)
)

# Agents run inside the container automatically
runtime = create_runtime(..., workspace=workspace)
```

**Container directory structure**

* `/workspace/<run_id>/repo/` (git clone inside container)
* `/workspace/<run_id>/.venv/` (venv inside container)
* Artifacts written to host-mounted volume: `artifacts/<run_id>/`

**Custom Docker image (optional)**

For faster startup, prebake dependencies:

```dockerfile
FROM python:3.11-slim
RUN pip install --no-cache-dir pip-audit uv
# Pre-install common tools
```

Use `DockerDevWorkspace` to auto-build from Dockerfile.

**Trade-offs**

* ✅ Strong isolation, reproducibility, security
* ❌ Slower startup (~2-5s per run for container creation)
* ❌ Requires Docker daemon running

---

### Workspace Policies

**Venv policy (simple + reliable)**

* Create `.venv` **only after** confirming:

  * repo cloned
  * `requirements.txt` exists
  * parsing passes directive gate
* All installs/audits run:

  * cwd: `/workspace/<run_id>/repo/` (inside container)
  * interpreter/tools: `/workspace/<run_id>/.venv/bin/...`

**Install policy (best-effort)**

* For baseline and final:

  * attempt `pip install -r requirements.txt` (record failures)
  * run `pip-audit -r requirements.txt --format json` regardless

This keeps the demo robust while still being "reasonable" about comparability.

---

### Configuration

`.env` variables:

```bash
# Docker configuration
DOCKER_BASE_IMAGE=python:3.11-slim
DOCKER_EXTRA_PORTS=false  # set "true" to enable VS Code Web on host_port+1
```

**Runtime setup**

```python
import os
from openhands_sdk import DockerWorkspace

workspace = DockerWorkspace(
    base_container_image=os.getenv("DOCKER_BASE_IMAGE", "python:3.11-slim"),
    extra_ports=os.getenv("DOCKER_EXTRA_PORTS", "false").lower() == "true",
)
```

---

### Security Implications

**Docker Sandbox Protection**

* Malicious `setup.py` scripts run in isolated container
* Network access can be restricted via Docker networking
* File system access limited to workspace mount
* **Still vulnerable to**: supply chain attacks affecting audit results, CPU/memory DoS

---

## 🧾 Requirements Parsing & Safety Gates

### Conservative parsing

Classify each non-empty, non-comment line as:

* `editable_spec` (safe patterns only)
* `directive_or_unsupported` (skip-worthy)
* `unknown` (treat as non-editable)

### Directive Handling (MVP default: STRICT_SKIP_ON_DIRECTIVES)

If **any** directive/include/index/resolver flags are present (examples):

* `-r`, `--requirement`, `-c`, `--constraint`
* `--index-url`, `--extra-index-url`, `--find-links`, `--trusted-host`
* `-e`, `--editable`
* VCS/URL/path installs (`git+`, `http(s)://`, `../`, `/abs/path`, etc.)

Then:

* do **not** run `pip install` or `pip-audit`
* write stubs + summary
* exit with `run_status = SKIPPED`

---

## 🔍 Scanning & Worklist

### Baseline scan (Coordinator)

Runs:

* `pip-audit -r requirements.txt --format json`
  Writes:
* `pip_audit_before.json`

### Worklist creation (Coordinator)

From audit results, build a serialized list of fix candidates:

* only items that map to **direct requirements entries**
* include:

  * package name
  * current spec (line + line number)
  * vulnerability IDs (CVE/OSV/etc)
  * fix versions (if provided by pip-audit)
  * `is_editable` + `skip_reason` if not

Coordinator may optionally OSV-enrich *at this stage* for summary context (best-effort).

---

## 🛠️ Fix Policy (Fixer Agent)

For each work item (one package at a time):

1. **Decide if editable**

   * If not editable → write patch note “skipped” with reason; return
2. **Apply safe patch strategy**

   * If `pip-audit` provides a minimal fixed version `F`:

     * `pkg==x` → `pkg>=F` (or `pkg==F` if you want stricter pinning)
     * `pkg>=x` → bump lower bound to `>=F` if needed
     * `pkg~=x.y` → bump to `~=<F major/minor compatible>` only if it still matches semantic intent; otherwise skip
     * `pkg` (unpinned) → pin to `>=F` (or `==F`)
3. **Best-effort install**

   * `pip install -r requirements.txt` (record errors in patch notes)
4. **Spot-check audit**

   * run `pip-audit -r requirements.txt --format json`
   * confirm the package’s vuln is removed or reduced
   * if the change worsens or is unclear → revert edit and record as failed
5. **Write `PATCH_NOTES_<pkg>.md`**

   * include:

     * what changed (old → new)
     * verification result
     * install result
     * OSV enrichment section (see next)

---

## 🧠 MCP Enrichment (OSV) Policy

### Best-effort, never blocking

* MCP failures must not fail the run.
* If unavailable:

  * Fixer writes: “OSV Enrichment: unavailable”
  * Coordinator summary records MCP status.

### Who can call MCP tools?

* **Coordinator**: optional enrichment for summary / worklist context
* **Fixer**: enrichment for the package it is patching (preferred for patch notes)

### Enrichment targets

* vulnerability ID lookups (CVE/OSV/GHSA)
* affected ranges / fixed versions (if available)
* short advisory summary (keep concise)

---

## ✅ Verification (Coordinator)

After all Fixer tasks complete (or none eligible):

1. `pip install -r requirements.txt` (best-effort)
2. `pip-audit -r requirements.txt --format json`
   Writes:

* `pip_audit_after.json`
* `pip_audit.json` (alias/copy of after)

---

## 📦 Artifacts (Always Produced)

Always write (even on SKIPPED/FAILED; use stubs as needed):

1. `artifacts/<run_id>/pip_audit_before.json`
2. `artifacts/<run_id>/pip_audit_after.json`
3. `artifacts/<run_id>/pip_audit.json` (alias of after)
4. `artifacts/<run_id>/cve_status.json`
5. `artifacts/<run_id>/SUMMARY.md`
6. `artifacts/<run_id>/PATCH_NOTES_<pkg>.md` (0..N)

### Stub schema (for skipped/failed audit artifacts)

```json
{"skipped": true, "reason_code": "...", "reason_detail": "...", "results": []}
```

---

## 🧾 `SUMMARY.md` (Suggested Content)

* run metadata:

  * `run_id`, timestamp
  * repo URL + commit hash (if available)
  * tool versions (python, pip, pip-audit, uv optional)
* status:

  * `SUCCESS | SKIPPED | FAILED`
  * counts: vulnerabilities before/after, packages fixed, packages skipped
* MCP:

  * enabled/disabled
  * status: OK/UNAVAILABLE/ERROR
  * short error summary (if any)
* results table:

  * package, vuln IDs (CVE-first), action (fixed/skipped), link to patch note

---

## 🖥️ Gradio UI Spec (Minimal)

Components:

* Repo URL input (`Textbox`)
* Run button
* Stage display (`Label/Markdown`)
* Progress bar
* Live log (`Textbox`, streamed)
* Status summary
* Artifact downloads (`File`):

  * `SUMMARY.md`
  * `cve_status.json`
  * `pip_audit_before.json`
  * `pip_audit_after.json` (or `pip_audit.json`)
  * `PATCH_NOTES_*` (list/dropdown)

UX rules:

* yield immediately on click (`Preflight started…`, progress ~5%)
* stream stages: `Preflight → Clone → Parse → Scan → Fix → Verify → Write`
* artifacts downloadable even on SKIPPED/FAILED

---

## 🔁 Runtime Flow (Step-by-Step)

```text
(1) UI click → immediate yield: Preflight, 5%

(2) Preflight (Coordinator)
    - create run_id
    - create artifacts/<run_id>/ (host) and /workspace/<run_id>/repo/ (container)
    - init MCP if enabled (best-effort), apply tool filtering
    - record MCP status

(3) Clone
    - git clone into /workspace/<run_id>/repo/ (container)
    - if requirements.txt missing → WRITE (stubs + summary) → DONE

(4) Parse
    - conservative parse + classify
    - if directives found → SKIPPED → WRITE stubs + summary → DONE

(5) Scan (Baseline)
    - create venv /workspace/<run_id>/.venv/ (container)
    - install pip-audit tooling
    - best-effort pip install -r requirements.txt
    - run pip-audit → pip_audit_before.json

(6) Fix loop (serialized)
    - build direct-only worklist
    - for each item:
        - Delegate → Fixer (pkg context)
        - Fixer edits, installs (best-effort), spot-check audits
        - Fixer writes PATCH_NOTES_<pkg>.md (with MCP enrichment if available)

(7) Verify (Final)
    - best-effort install
    - run pip-audit → pip_audit_after.json (+ pip_audit.json alias)

(8) Write
    - write cve_status.json + SUMMARY.md
    - UI shows downloads + final status
```

---

## 🔧 Model Switching Requirement

Changing models requires **only** updating:

* `COORDINATOR_OPENROUTER_MODEL`
* `FIXER_OPENROUTER_MODEL`

No agent code changes.
