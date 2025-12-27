# Coordinator setup

## Modules breakdown
- `src/agents/coordinator/coordinator.py`: includes thin orchestration + public API (generator and glue) and the run pipeline steps (clone, parse, baseline_audit, fix_worklist, finalize) returning structured results.
- `src/agents/coordinator/artifacts.py`: all artifact I/O (`SUMMARY.md`, audit JSON, stubs, `cve_status.json`).
- `src/agents/coordinator/requirements_parser.py`: parsing + directive gating + entry dataclasses.
- `src/agents/coordinator/audit.py`: venv + pip-audit execution + count helpers.
- `src/agents/coordinator/reporting.py`: summary formatting + rows; spot-check + verification note appending.
- `src/agents/coordinator/models.py`: shared dataclasses (`RequirementEntry`, `WorklistItem`, `RunContext`, `RunResult`).

## Modules tasks
1) **Create shared models**
   - Move dataclasses to `src/agents/coordinator/models.py` and update imports.
   - Add new `RunContext` and `RunResult` to carry run-scoped data cleanly.

2) **Extract parsing**
   - Move requirement parsing helpers into `src/agents/coordinator/requirements_parser.py`.
   - Keep parsing behavior identical; re-export functions if needed for compatibility.

3) **Extract audit logic**
   - Move venv + pip-audit helpers into `src/agents/coordinator/audit.py`.
   - Return structured results for baseline/final/spot-check to standardize error handling.

4) **Extract reporting**
   - Move summary formatting and spot-check + verification note appending into
     `src/agents/coordinator/reporting.py`.
   - Use `RunContext` to pass paths rather than threading many args.

5) **Extract artifacts**
   - Move artifact writing + stub logic into `src/agents/coordinator/artifacts.py`.

6) **Refactor coordinator**
   - Keep the pipeline steps inside `src/agents/coordinator/coordinator.py`.
   - Replace inline logic with calls into `requirements_parser`, `audit`, `reporting`,
     and `artifacts` while keeping the generator flow unchanged.

## ASCII diagram
```
+-----------------------------------------+
|        coordinator.py (package)         |
|  public API + generator + pipeline      |
|  clone -> parse -> audit -> fix ->      |
|  finalize                               |
+-----+--------+--------+--------+--------+
      |        |        |        |
      v        v        v        v
-------------+  +------------+  +----------------------+
| requirements | |  audit.py  |  |     reporting.py    |
| _parser.py   | |            |  | summary + verify     |
+-------------+ +------------+ +----------------------+
      \            /                 |
       \          /                  |
        v        v                   v
        +---------------------------------------------+
        |              artifacts.py                  |
        |  audit JSON, SUMMARY.md, stubs, cve_status  |
        +---------------------------------------------+
                           |
                           v
        +---------------------------------------------+
        |                 models.py                  |
        | RunContext / RunResult / RequirementEntry / |
        | WorklistItem                                |
        +---------------------------------------------+
```


