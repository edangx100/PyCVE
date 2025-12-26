# PyCVE Implementation Todos

Each task below delivers a small, testable increment that you can interact with and validate before moving to the next step.

---

## Phase 1: Foundation & Validation

### ✅ Task 1: Project Setup & Environment Validation
- [x] Create `.env` file with required variables (`OPENROUTER_API_KEY`, model configs)
- [x] Create `requirements.txt` with initial dependencies (openhands-sdk, gradio, python-dotenv)
- [x] Create basic project structure (`src/`, `artifacts/`, `tests/`)
- [x] Write a minimal script that validates OpenRouter API connectivity
- [x] **test**: Run the script and confirm you see a successful API response

---

### ✅ Task 2: OpenHands SDK "Hello World"
- [x] Create a minimal single-agent script using OpenHands SDK
- [x] Configure OpenRouter LLM for the agent
- [x] Agent executes a simple command (e.g., `echo "Hello from OpenHands"`) via TerminalTool
- [x] Print the agent's output to console
- [x] **test**: Run script and see the agent successfully execute a terminal command

---

### ✅ Task 3: Built-in Tools Verification
- [x] Extend the test agent to use DelegateTool (delegate to a sub-agent)
- [x] Use FileEditorTool to create/edit a test file
- [x] Use TaskTrackerTool to log a task
- [x] Print summary of which built-in tools work
- [x] **test**: Confirm all 4 required built-in tools are functional

---

## Phase 2: Minimal UI & Core Flow

### ✅ Task 4: Gradio UI Skeleton
- [x] Create `app.py` with Gradio interface
- [x] Add Textbox for GitHub repo URL input
- [x] Add "Run Scan" button
- [x] Add Textbox for live log output
- [x] Button click returns "Preflight started..." message
- [x] **test**: Launch Gradio UI, enter a URL, click button, see acknowledgment message

---

### ✅ Task 5: Coordinator Clone Repo (Local Workspace)
- [x] Create a new folder `src/agents`
- [x] Create Coordinator agent within `src/agents` that accepts GitHub URL. Agent is based on OpenHands software agent SDK: https://docs.openhands.dev/sdk/getting-started
- [x] Agent clones repo to `workspace/<run_id>/repo/` (local filesystem for now)
- [x] Stream clone progress to Gradio UI
- [x] Display success/failure message with repo path
- [x] **test**: Enter a real GitHub URL, see repo cloned locally, verify files exist

---

### ✅ Task 6: Requirements.txt Detection & Parsing
- [x] Coordinator checks if `requirements.txt` exists in cloned repo
- [x] Implement conservative parsing logic (editable vs directive classification)
- [x] Implement directive gating (SKIP if directives found)
- [x] Display parse results in UI (editable packages, directives found, skip reason)
- [x] **test**: Test with 2 repos: one simple requirements.txt, one with directives; verify correct behavior

---

## Phase 3: Scanning & Worklist

### ✅ Task 7: pip-audit Baseline Scan
- [x] Create venv in workspace after successful parse
- [x] Install pip-audit in venv
- [x] Run `pip-audit -r requirements.txt --format json`
- [x] Save output to `artifacts/<run_id>/pip_audit_before.json`
- [x] Display vulnerability count in UI
- [x] **test**: Use a repo with known vulnerabilities (or create test requirements.txt), see JSON artifact generated

---

### ✅ Task 8: Direct Dependency Worklist
- [x] Parse pip-audit JSON results
- [x] Filter to only direct dependencies (match against parsed requirements.txt)
- [x] Build worklist with: pkg name, current spec, vuln IDs, fix versions, editability
- [x] Display worklist table in UI (package, CVEs, current version, suggested fix)
- [x] **test**: Verify worklist shows only direct dependencies, not transitives

---

## Phase 4: Fixing (Single Package MVP)

### ✅ Task 9: Fixer Agent (Single Package)
- [x] Create Fixer agent skeleton
- [x] Coordinator delegates ONE package from worklist to Fixer (use DelegateTool)
- [x] Fixer receives package context (name, current spec, vuln, fix version)
- [x] Fixer applies safe edit to requirements.txt (use FileEditorTool). Before modifying requirements.txt, create a duplicate and save it as requirements_before.txt
- [x] Fixer writes `PATCH_NOTES_<pkg>.md` with before/after
- [x] Display patch notes content in UI
- [x] **test**: See requirements.txt edited, patch notes generated for one package

---

### ✅ Task 10: Spot-Check Verification
- [x] After Fixer edits requirements.txt, re-run pip-audit
- [x] Compare vulnerability count for that specific package (before vs after)
- [x] If worse, revert edit and mark as failed in patch notes
- [x] Update patch notes with verification result
- [x] Display verification status in UI
- [x] **test**: Confirm patch notes show "verified: vuln removed" or "verified: failed"

---

### ✅ Task 11: Multi-Package Fix Loop
- [x] Coordinator iterates through entire worklist (serialized)
- [x] Delegate each package to Fixer one at a time
- [x] Display progress bar (e.g., "Fixing package 2/5...")
- [x] Collect all patch notes
- [x] **test**: Use repo with 3+ vulnerable packages, see all get processed sequentially

---

## Phase 5: Final Verification & Artifacts

### ✅ Task 12: Final Audit & Comparison
- [x] After all fixes, run final `pip-audit -r requirements.txt --format json`
- [x] Save to `artifacts/<run_id>/pip_audit_after.json`
- [x] Create alias `artifacts/<run_id>/pip_audit.json` (copy of after)
- [x] Display before/after vulnerability counts in UI
- [x] **test**: See final audit artifact, compare before/after manually

---

### ✅ Task 13: cve_status.json Generation
- [x] Create `cve_status.json` with structure:
  - `{ "before": [...], "after": [...], "fixed": [...], "remaining": [...] }`
- [x] Include CVE IDs, package names, fix status
- [x] Save to artifacts directory
- [x] Display summary in UI (X fixed, Y remaining)
- [x] **test**: Open JSON file, verify it accurately reflects changes

---

### ✅ Task 14: SUMMARY.md Generation
- [x] Generate `SUMMARY.md` with all required sections (per plan.md:469-488)
- [x] Include: run metadata, status, counts, results table with links to patch notes
- [x] Save to artifacts directory
- [x] Display summary in UI or provide download link
- [x] **test**: Read SUMMARY.md, verify it's clear and complete

---

### ✅ Task 15: Artifact Download Links
- [x] Add Gradio File components for all artifacts:
  - SUMMARY.md
  - cve_status.json
  - pip_audit_before.json
  - pip_audit_after.json
  - All PATCH_NOTES_*.md files
- [x] Artifacts downloadable even on SKIPPED/FAILED runs (use stubs if needed)
- [x] **test**: Complete a full run, download all artifacts, verify they're valid

---

## Phase 6: Production Hardening

### ✅ Task 16: Docker Workspace Integration
- [ ] Create `DockerWorkspace` configuration (per plan.md:226-238)
- [ ] Set `DOCKER_BASE_IMAGE` in .env
- [ ] Update Coordinator to use Docker workspace instead of local
- [ ] Verify repo clone, venv creation, pip-audit all work inside container
- [ ] Workspace path: `/workspace/<run_id>/repo/` (container), artifacts on host
- [ ] **test**: Run full scan, verify it works in Docker, artifacts appear on host

---

### ✅ Task 17: Error Handling & Stub Artifacts
- [ ] Handle missing requirements.txt → write stub artifacts + SUMMARY
- [ ] Handle directive detection → SKIPPED status + stub artifacts
- [ ] Handle failed git clone → FAILED status + stub artifacts
- [ ] Handle pip-audit failures → record in SUMMARY, continue gracefully
- [ ] **test**: Test failure scenarios (bad URL, no requirements.txt), verify stubs generated

---

### ✅ Task 18: Install Policy (Best-Effort)
- [ ] Before baseline audit: attempt `pip install -r requirements.txt`
- [ ] Record install failures but continue with audit
- [ ] Before final audit: attempt install again
- [ ] Fixer agent: best-effort install after each edit
- [ ] Log install results in patch notes
- [ ] **test**: Use requirements.txt with uninstallable package, verify audit still runs

---

## Phase 7: MCP Integration (Optional Enrichment)

### ✅ Task 19: OSV-MCP Server Setup
- [ ] Clone/install `EdenYavin/OSV-MCP` to location specified in .env
- [ ] Add `OSV_MCP_DIR` and `OSV_MCP_ENABLED` to .env
- [ ] Configure MCP in OpenHands runtime (per plan.md:172-181)
- [ ] Run preflight check: verify MCP server starts, log tool names
- [ ] **test**: Enable MCP, run preflight, see OSV tools listed (or graceful unavailable message)

---

### ✅ Task 20: MCP Tool Filtering
- [ ] Implement regex-based tool filtering: `r"^(osv|OSV|osv_).*"`
- [ ] Add preflight check: verify built-in tools (DelegateTool, TerminalTool, etc.) still present
- [ ] If built-ins missing → FAIL FAST with clear error message
- [ ] If OSV tools missing → mark MCP unavailable, continue without enrichment
- [ ] **test**: Toggle filter on/off, verify built-ins always present, OSV tools filtered correctly

---

### ✅ Task 21: OSV Enrichment in Patch Notes
- [ ] Fixer agent: if MCP available, query OSV for CVE/GHSA details
- [ ] Add "OSV Enrichment" section to PATCH_NOTES_<pkg>.md
- [ ] Include: advisory summary, affected ranges, fixed versions
- [ ] If MCP unavailable: write "OSV Enrichment: unavailable"
- [ ] **test**: Compare patch notes with/without MCP, verify enrichment appears

---

### ✅ Task 22: MCP Status in SUMMARY.md
- [ ] Add MCP section to SUMMARY.md (enabled/disabled, status, error summary)
- [ ] Record MCP tool count and availability
- [ ] **test**: Run with MCP enabled vs disabled, verify SUMMARY reflects correct status

---

## Phase 8: Polish & Edge Cases

### ✅ Task 23: Progress Bar & Stage Display
- [ ] Implement 8-stage workflow: Preflight → Clone → Parse → Scan → Fix → Verify → Write → Done
- [ ] Update Gradio progress bar at each stage (5%, 15%, 25%, 40%, 60%, 80%, 95%, 100%)
- [ ] Display current stage name in UI
- [ ] **test**: Watch progress bar and stage labels update during full run

---

### ✅ Task 24: Streaming Live Logs
- [ ] Stream agent output to Gradio live log Textbox
- [ ] Include: git clone output, pip-audit output, fix progress
- [ ] Format with timestamps or stage prefixes
- [ ] **test**: Watch live log populate in real-time during run

---

### ✅ Task 25: Model Switching Configuration
- [ ] Document in README how to change models via .env
- [ ] Test with different OpenRouter models (if available)
- [ ] Verify no code changes needed to switch models
- [ ] **test**: Change model in .env, re-run, verify new model is used

---

### ✅ Task 26: Custom Docker Image (Optional)
- [ ] Create Dockerfile with pre-installed pip-audit, uv
- [ ] Add `DOCKER_EXTRA_PORTS` config for VS Code Web debugging
- [ ] Update DockerWorkspace to use custom image
- [ ] **test**: Build custom image, verify faster startup time

---

### ✅ Task 27: End-to-End Integration Test
- [ ] Create test script that runs full workflow on 3 test repos:
  - Simple repo with 2-3 fixable vulnerabilities
  - Repo with directives (should SKIP)
  - Repo without requirements.txt (should write stubs)
- [ ] Verify all artifacts generated correctly for each case
- [ ] **test**: Run test suite, all 3 scenarios pass

---

### ✅ Task 28: Documentation
- [ ] Write README.md with:
  - Setup instructions (dependencies, .env config, Docker setup)
  - Usage guide (how to run Gradio app)
  - Architecture overview (linking to plan.md)
  - Troubleshooting section
- [ ] Document all .env variables with examples
- [ ] **test**: Follow README from scratch on clean machine (or have someone else test)

---

## Notes

- **Don't skip ahead**: Each task builds on the previous one. Test thoroughly before moving on.
- **Commit after each task**: Makes progress visible and rollback easy.
- **User validation is key**: If something doesn't work as expected, pause and fix before proceeding.
- **MCP is optional**: Tasks 19-22 can be deferred if you want to get core functionality working first.