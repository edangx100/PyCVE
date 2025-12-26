# Multi Vulnerability Test Repo

This repo is for testing Task 11: the multi-package fix loop.

## Dependency choice

Each direct dependency is an older release that pip-audit commonly reports as
vulnerable, so the worklist should include multiple entries.

- requests==2.19.1
- jinja2==2.10
- pyyaml==5.1
- urllib3==1.23


## Expected behavior

- pip-audit reports 3+ vulnerable direct dependencies.
- The worklist shows multiple packages (4 in this fixture).
- Coordinator delegates each package to Fixer sequentially.
- UI shows progress text like "Fixing package 2/4...".
- Patch notes are collected for every package.

If pip-audit stops reporting vulnerabilities for any entry, swap in an older
release of that package or replace it with another known vulnerable package.
