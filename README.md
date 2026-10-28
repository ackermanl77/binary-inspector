# Binary Inspector

Binary Inspector is a small Windows-focused application for **static inspection** of Windows PE executables (`.exe` and `.dll`). It reads the selected file as data; it never launches, injects into, patches, or modifies the executable.

The app's built-in analysis reports:

- SHA-256, file size, and file name
- PE architecture, timestamp, optional-header format, and entry-point RVA
- Sections, sizes, flags, and entropy (a packing indicator, not a malware verdict)
- Imported DLLs and functions when the import table is valid
- Exported symbols and delay-loaded imports
- Debug records and CodeView PDB paths, version resources, and CLR runtime metadata
- Whether a certificate table is declared; optional Windows Authenticode trust verification
- A bounded sample of printable ASCII and UTF-16LE strings

Optional integrations add:

- Native entry-point disassembly through a locally installed Rizin executable
- C# decompilation through a locally installed ILSpyCmd
- Behavior observations imported from a separately isolated sandbox as normalized JSON

## Run

Requires Python 3.10+ and Tkinter (included with standard Windows Python installers).

```powershell
python -m binary_inspector
```

Choose **Open executable** to analyze a file. Use **Save report** to export the displayed report as JSON. On Windows, **Verify signature** checks the selected file against cached local trust data. The app does not submit samples or reports to a network service.

### Build the Windows executable

On Windows with Python installed:

```powershell
.\build.ps1
```

The script creates an isolated `.venv`, installs the pinned PyInstaller build dependency, and produces `dist\BinaryInspector.exe`. Launch that executable, click **Open executable**, select an authorized `.exe` or `.dll`, and review the static report. It also checks the packaged app with `--self-test`. The optional Rizin/ILSpy integrations still require those tools installed separately on the analysis machine.

The optional disassembly/decompilation buttons invoke only the explicitly named local tool, with no shell, a time limit, and an 8 MiB combined output limit. Install Rizin and/or ILSpyCmd yourself; the app does not download tools. Set `BINARY_INSPECTOR_RIZIN` or `BINARY_INSPECTOR_ILSPYCMD` to a specific executable path if the tool is not on `PATH`.

For command-line use:

```powershell
python -m binary_inspector path\to\program.exe --json report.json
```

Optional command-line integrations:

```powershell
python -m binary_inspector path\to\native.exe --disassemble --json report.json
python -m binary_inspector path\to\managed.exe --decompile-dotnet --json report.json
python -m binary_inspector path\to\sample.exe --sandbox-report sandbox-observations.json --json report.json
python -m binary_inspector path\to\program.exe --verify-signature --json report.json
```

`--verify-signature` invokes the Windows Authenticode trust API without launching the file. It uses cached URL retrieval only and does not check revocation; non-Windows platforms report that verification is unavailable. The result is `trusted`, `unsigned`, `untrusted`, or `unable_to_verify` with the Windows status code when available. Trust is not a safety verdict.

### Sandbox behavior reports

Binary Inspector **does not execute samples or create/operate a sandbox**. Run authorized samples only in a separately configured disposable VM/sandbox with networking disabled unless specifically required, no personal accounts/data, no shared writable folders, and a revertible snapshot. Export observations as JSON using schema `binary-inspector-sandbox-v1`; see [`docs/sandbox-report-example.json`](docs/sandbox-report-example.json). Imports are limited to 5 MiB and 5,000 events. The optional source SHA-256 is compared with the inspected file and any mismatch is shown; imported observations are not independently verified.

Run tests:

```powershell
python -m unittest discover -s tests -v
```

## Safety and limitations

- Only analyze files you own or are authorized to inspect. The analyzer does not execute the selected file.
- Parsing is bounded to 256 MiB per file; malformed or unsupported input is reported as an error rather than guessed.
- Import parsing has an aggregate limit of 100,000 imported functions across normal and delay-loaded imports. Directory, resource, export, debug, and version parsing also have explicit count and nesting limits; exceeding a limit reports an analysis error rather than silently presenting incomplete data.
- Imported function names and other PE metadata text are capped at 16 MiB; version resources are capped at 4 MiB each and 16 MiB total.
- PE metadata and strings are clues, not a safety determination. High entropy is not proof of packing or maliciousness.
- A declared certificate table does **not** mean the signature is valid or trusted. Optional Windows verification uses the local trust policy with cached URL data and no revocation check; an accepted signature does not establish that a file is safe.
- Disassembly/decompilation rely on optional third-party parsers of untrusted data; keep them updated and run them under a least-privileged account. They are not a security verdict.
- Sandbox behavior analysis is an import-only workflow. This app never launches a sample, configures a VM, or claims that an imported report is complete or authentic.
- The report may contain strings embedded in the binary. Review it before sharing.

## Layout

- `binary_inspector/pe.py` — bounded PE parser and report data model
- `binary_inspector/external_tools.py` — bounded local Rizin/ILSpyCmd integrations
- `binary_inspector/sandbox_report.py` — normalized, bounded sandbox report importer
- `binary_inspector/signature.py` — optional Windows Authenticode trust verification
- `binary_inspector/gui.py` — Tkinter desktop interface
- `binary_inspector/__main__.py` — desktop and command-line entry point
- `launcher.py` and `build.ps1` — PyInstaller entry point and Windows build script
- `tests/` — generated PE fixtures; no third-party executable samples
