# Binary Inspector

Binary Inspector is a small Windows-focused application for **static inspection** of Windows PE executables (`.exe` and `.dll`). It reads the selected file as data; it never launches, injects into, patches, or modifies the executable.

The app's built-in analysis reports:

- SHA-256, SHA-1, MD5, the imphash (computed as pefile does, so it matches threat-intel feeds),
  each section's SHA-256, file size and name, and the header checksum against the computed one
- PE architecture, timestamp, optional-header format, and entry-point RVA. A reproducible build's
  timestamp is a content hash, not a date, and is shown that way; a future date is flagged
- Sections with file offsets, sizes, named flags (code, execute, write...), and entropy (a packing
  indicator, not a malware verdict)
- Security mitigations from the headers: ASLR (with relocations kept), high-entropy ASLR, DEP,
  Control Flow Guard, CET shadow-stack compatibility, SafeSEH, the /GS stack cookie,
  FORCE_INTEGRITY, TLS callbacks (code that runs before the entry point), sections that are both
  writable and executable, and the linker's Rich header (tool product ids, builds, object counts)
- The overlay (data after the last section): offset, size, entropy, SHA-256, how much of it is the
  signature, and a hint when it looks like a known container (PyInstaller, NSIS, Inno Setup, ZIP,
  7-Zip, RAR, CAB, MSI, an embedded PE)
- The application manifest: requested execution level, uiAccess, autoElevate, DPI awareness and
  dependent assemblies
- Imported DLLs and functions when the import table is valid
- Exported symbols and delay-loaded imports
- Debug records (named: CODEVIEW, POGO, REPRO...) and CodeView PDB paths, resources with their
  type names (RT_ICON, RT_VERSION...) and file offsets, version resources, and CLR runtime metadata
- Whether a certificate table is declared; optional Windows Authenticode trust verification, embedded or through a system catalog, with the signer
- .NET metadata: assembly name, version, culture and public key token, the module and its MVID,
  referenced assemblies, P/Invoke imports (native functions called from managed code), CLR flags,
  ReadyToRun, and metadata table row counts. Damaged metadata (obfuscators do this on purpose)
  stops this part with a stated error; the rest of the report is unaffected
- Hints, each a pattern match and never a verdict: imported functions grouped by what they are
  commonly used for (process injection, input capture, network, cryptography, debugger
  detection, services, starting programs, privileges, run-time loading); the packer, installer or
  toolchain (UPX, VMProtect, Themida, ASPack, MPRESS, PyInstaller, Nuitka, NSIS, Inno Setup, Go,
  Rust, Delphi, AutoIt, MinGW, the Visual Studio release from the Rich header)
- A bounded sample of printable ASCII and UTF-16LE strings; the ones that look like URLs, IP
  addresses, e-mail addresses, registry keys, paths or Base64 are tagged and kept first

Optional integrations add:

- Native entry-point disassembly through a locally installed Rizin executable
- C# decompilation through a locally installed ILSpyCmd
- Behavior observations imported from a separately isolated sandbox as normalized JSON

## Run

Requires Python 3.10+ and Tkinter (included with standard Windows Python installers).

```powershell
python -m binary_inspector
```

Choose **Open executable** to analyze a file. The report is split into tabs:

- **Summary:** the key facts (hashes, architecture, timestamp, signature, version) and notes on what deserves a look first. The notes are colour-coded: green for a protection in place, orange for something to check. They are hints, not a verdict.
- **Sections, Imports, Exports, Resources:** tables. Imports are grouped by DLL, and version fields appear under their resource.
- **Security:** mitigations, TLS callbacks, the manifest, the overlay, debug records and the Rich header.
- **.NET:** the assembly's identity, its references, P/Invoke imports and metadata tables.
- **Strings:** a filter box (Ctrl+F jumps there) and a Kind list (URL, IP, path... or every notable one).
- **Tools:** the output of the optional buttons.
- **Full report:** the whole report as text.

**Compare...** analyses a second file and lists what changed (sections, imports, exports, version
fields, mitigations, toolchain). **YARA scan...** matches your rules (a `.yar` file, or Cancel and
pick a folder of them) against the file in memory; it needs `yara-python` (see below). **File >
Analyze folder (batch)** writes a report per file and a `summary.csv`. **File > Open recent** lists
the last ten files, and **View** switches between a light theme, a dark one, and following Windows;
both are remembered in `%APPDATA%\BinaryInspector\settings.json`.

Click a column header to sort it (numbers and hex values sort by value; click again to reverse), and press Ctrl+C to copy the selected rows as tab-separated text. On a scaled display (125 %, 200 %...) the window is drawn at the display's resolution, so text stays sharp.

Use **Save report** to export the displayed report as JSON. On Windows, **Verify signature** checks the selected file against cached local trust data. The app does not submit samples or reports to a network service.

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
python -m binary_inspector old\app.exe --compare new\app.exe --json changes.json
python -m binary_inspector path\to\program.exe --yara rules\ --json report.json
python -m binary_inspector C:\samples --out reports\ --recursive --verify-signature
```

`--compare` adds an `extended_analysis.comparison` section. `--yara` needs the optional
`yara-python` package (`python -m pip install yara-python`; at the time of writing it has no
Windows wheel for Python 3.14, so use Python 3.10-3.13); without it the scan reports how to
install it. The packaged executable does not include it, so YARA scanning works when running
from source. Given a folder, `--out` writes one JSON report per `.exe`/`.dll`/`.sys`/... file
and a `summary.csv` with a row each (hashes, architecture, signature, mitigations, .NET,
overlay, toolchain, import behaviours, notable strings, or the error for a file that could not
be analysed); `--recursive` includes subfolders.

`--verify-signature` invokes the Windows Authenticode trust API without launching the file. It uses cached URL retrieval only and does not check revocation; non-Windows platforms report that verification is unavailable. Most Windows system files have no embedded signature and are signed through a security catalog instead, so a file without one is hashed (read only) and looked up in the system catalogs; if a catalog lists it, that catalog signature is verified. The result is `trusted`, `unsigned`, `untrusted`, or `unable_to_verify` with the Windows status code when available, plus `source` (`embedded` or `catalog`), the signing certificate's `signer` and `issuer`, and the `catalog` file when there is one. A changed copy of a catalog-signed file is no longer listed and comes out `unsigned`. Trust is not a safety verdict.

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
- PE metadata and strings are clues, not a safety determination. High entropy is not proof of packing or maliciousness, a container hint in the overlay is a byte-pattern match, and a missing mitigation is a hardening gap, not evidence of intent.
- The import and delay-import directory sizes are treated as the loader treats them: descriptors are read up to the all-zero terminator, which must lie within the declared size rounded up to a whole descriptor (some linkers, such as MinGW ld, declare the whole `.idata` section).
- A declared certificate table does **not** mean the signature is valid or trusted. Optional Windows verification uses the local trust policy with cached URL data and no revocation check; an accepted signature does not establish that a file is safe.
- Disassembly/decompilation rely on optional third-party parsers of untrusted data; keep them updated and run them under a least-privileged account. They are not a security verdict.
- Sandbox behavior analysis is an import-only workflow. This app never launches a sample, configures a VM, or claims that an imported report is complete or authentic.
- The report may contain strings embedded in the binary. Review it before sharing.

## Layout

- `binary_inspector/pe.py` — bounded PE parser and report data model
- `binary_inspector/pe_details.py` — readable names, timestamp meaning, overlay, manifest and security mitigations
- `binary_inspector/external_tools.py` — bounded local Rizin/ILSpyCmd integrations
- `binary_inspector/sandbox_report.py` — normalized, bounded sandbox report importer
- `binary_inspector/signature.py` — optional Windows Authenticode trust verification (embedded and catalog signatures)
- `binary_inspector/gui.py` — Tkinter desktop interface (tabs, sortable tables)
- `binary_inspector/findings.py` — the Summary tab's notes (hints drawn from the report)
- `binary_inspector/triage.py` — import behaviour groups, packer/toolchain hints, string categories
- `binary_inspector/dotnet.py` — .NET metadata tables (ECMA-335)
- `binary_inspector/ordinals.py` — pefile's ordinal names (MIT), for a matching imphash
- `binary_inspector/compare.py`, `batch.py`, `yara_scan.py` — comparing files, batch mode, optional YARA
- `binary_inspector/settings.py` — recent files and the theme
- `binary_inspector/__main__.py` — desktop and command-line entry point
- `launcher.py` and `build.ps1` — PyInstaller entry point and Windows build script
- `tests/` — generated PE fixtures; no third-party executable samples
