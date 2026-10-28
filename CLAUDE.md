# CLAUDE.md

Guidance for Claude Code in this repository. User-facing docs: [README.md](README.md).

## What this is

A static, non-executing Windows PE inspector: a bounded PE parser (`binary_inspector/pe.py`), a
Tkinter GUI (`gui.py`), a CLI (`__main__.py`), optional local Rizin/ILSpyCmd integrations
(`external_tools.py`), Windows Authenticode verification (`signature.py`) and a sandbox-report
importer (`sandbox_report.py`). Standard library only at runtime; PyInstaller for the build.

## Commands

```powershell
python -m binary_inspector                                    # GUI
python -m binary_inspector path\to\program.exe --json out.json
python -m unittest discover -s tests -v
.\build.ps1                                                   # dist\BinaryInspector.exe, then --self-test
```

## Rules

- **Never execute, load or modify the inspected file.** Everything is read as bytes. External tools
  run without a shell, with a time limit and an output cap.
- **Every parser loop is bounded** (counts, nesting, bytes, aggregate budgets). Exceeding a limit
  raises `PEFormatError`; never return silently truncated data.
- Tests generate their PE fixtures; don't add third-party executables or real malware samples.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost), then `graphify export wiki` -- the git hooks rebuild graph.json after each commit/checkout but never the wiki.
- graphify-out/ is gitignored: every clone builds its own graph (`/graphify`), and the git hooks (`graphify hook install`) keep it current. Do not commit it or suggest skipping the rebuild or its hooks.
- Community names live in graphify-out/.graphify_labels.json (curated); a community a rebuild creates or reshapes gets a hub-name fallback in `.graphify_labels.pending.json` (e.g. a bare file or test name). When the report shows such names, rename them there (2-5 plain words) and run `graphify cluster-only .`.
