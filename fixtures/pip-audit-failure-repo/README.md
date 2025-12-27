# Pip-Audit Failure Test Repo

This repo intentionally triggers a pip-audit failure so Task 17 can be
validated (record failure in SUMMARY.md and continue gracefully).

## Why it fails

The requirements file includes an invalid requirement line:

- `this is not a valid requirement`

pip-audit should exit with a non-zero status and produce no JSON output.

## Expected behavior

- Parsing succeeds (no directives), but one unknown line is reported.
- Baseline pip-audit fails with an error about the invalid requirement.
- SUMMARY.md records the pip-audit failure reason.
- Stub artifacts are still produced for the run.