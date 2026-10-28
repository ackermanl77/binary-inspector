"""Tkinter interface for safe, static PE inspection."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from . import findings, settings
from .external_tools import decompile_dotnet, disassemble_native
from .pe import Analysis, PEFormatError, analyze_file
from .sandbox_report import SandboxReportError, load_sandbox_report
from .signature import verify_authenticode
from . import triage


def sort_key(value: str) -> tuple[int, float, str]:
    """Numbers (with thousands separators) and 0x values sort by value, before text."""
    text = str(value).replace(",", "").strip()
    try:
        number = int(text, 16) if text.lower().startswith("0x") else float(text)
    except ValueError:
        return (1, 0.0, str(value).lower())
    return (0, float(number), "")


class InspectorWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Binary Inspector - Static PE Analysis")
        # Sizes below are for 96 DPI; on a scaled display (125%, 200%...) they grow with it.
        self._scale = max(1.0, self.root.winfo_fpixels("1i") / 96)
        width = min(self._px(1100), int(self.root.winfo_screenwidth() * 0.9))
        # 80 % leaves room for the title bar and the taskbar.
        height = min(self._px(760), int(self.root.winfo_screenheight() * 0.8))
        self.root.geometry(f"{width}x{height}")
        self._style = ttk.Style(self.root)
        self._native_theme = self._style.theme_use()
        self._settings = settings.load()
        self._results: queue.Queue[
            tuple[Path, Analysis | None, str | None, dict[str, Any] | None]
        ] = queue.Queue()
        self._analysis: Analysis | None = None
        self._input_path: Path | None = None
        self._extensions: dict[str, dict[str, Any]] = {}
        self._sort_state: dict[str, tuple[str, bool]] = {}
        self._tree_tables: set[str] = set()  # tables with a tree column (#0) to copy too
        self._build()
        self.apply_theme(self._settings["theme"])
        self.root.after(100, self._poll_results)

    # ---- theme (light, dark, or as Windows is set) ----

    _PALETTES = {
        "light": {"bg": "#f3f3f3", "fg": "#1b1b1b", "field": "#ffffff", "select": "#cfe0fc", "selected_fg": "#1b1b1b",
                  "accent": "#0b57d0", "warn": "#a33a00", "ok": "#1d6b2f", "border": "#c8c8c8"},
        "dark": {"bg": "#202124", "fg": "#e8eaed", "field": "#2b2c30", "select": "#3d5a99", "selected_fg": "#ffffff",
                 "accent": "#8ab4f8", "warn": "#ffb070", "ok": "#81c995", "border": "#44464b"},
    }

    def apply_theme(self, choice: str) -> None:
        """"system" follows Windows' app mode. Light keeps the native look; dark switches to the
        "clam" theme, whose colours can all be set."""
        self._settings["theme"] = choice
        if hasattr(self, "theme_choice"):
            self.theme_choice.set(choice)
        dark = choice == "dark" or (choice == "system" and settings.windows_prefers_dark())
        palette = self._PALETTES["dark" if dark else "light"]
        style = self._style
        style.theme_use("clam" if dark else self._native_theme)
        style.configure("Treeview", rowheight=self._px(22))
        # Tabs: padding and a coloured label show which one is open (the native theme draws no edge).
        style.configure("TNotebook.Tab", padding=(self._px(10), self._px(3)))
        style.map("TNotebook.Tab", foreground=[("selected", palette["accent"])])
        if dark:
            style.configure(".", background=palette["bg"], foreground=palette["fg"], fieldbackground=palette["field"],
                            bordercolor=palette["border"], lightcolor=palette["bg"], darkcolor=palette["bg"],
                            troughcolor=palette["field"], insertcolor=palette["fg"])
            style.configure("Treeview", background=palette["field"], fieldbackground=palette["field"],
                            foreground=palette["fg"])
            style.configure("Treeview.Heading", background=palette["bg"], foreground=palette["fg"])
            style.configure("TNotebook", background=palette["bg"])
            style.configure("TNotebook.Tab", background=palette["bg"])
            style.map("TNotebook.Tab", background=[("selected", palette["field"])])
            style.configure("TButton", background=palette["field"])
            style.map("TButton", background=[("disabled", palette["bg"]), ("active", palette["select"])],
                      foreground=[("disabled", "#8a8c91")])
            style.configure("TCombobox", fieldbackground=palette["field"], background=palette["field"],
                            arrowcolor=palette["fg"])
            style.map("TCombobox", fieldbackground=[("readonly", palette["field"])],
                      foreground=[("readonly", palette["fg"])], selectbackground=[("readonly", palette["field"])],
                      selectforeground=[("readonly", palette["fg"])])
            self.root.option_add("*TCombobox*Listbox.background", palette["field"])
            self.root.option_add("*TCombobox*Listbox.foreground", palette["fg"])
            style.configure("TEntry", fieldbackground=palette["field"])
            for scrollbar in ("TScrollbar", "Horizontal.TScrollbar", "Vertical.TScrollbar"):
                style.configure(scrollbar, background=palette["field"], troughcolor=palette["bg"],
                                arrowcolor=palette["fg"], bordercolor=palette["border"])
        style.map("Treeview", background=[("selected", palette["select"])],
                  foreground=[("selected", palette["selected_fg"])])
        self.root.configure(background=palette["bg"])
        for text in (self.output, self.tools_output):
            text.configure(background=palette["field"], foreground=palette["fg"], insertbackground=palette["fg"])
        self.findings_table.tag_configure(findings.WARN, foreground=palette["warn"])
        self.findings_table.tag_configure(findings.OK, foreground=palette["ok"])
        settings.save(self._settings)

    def _build(self) -> None:
        toolbar = ttk.Frame(self.root, padding=8)
        toolbar.pack(fill=tk.X)
        self.open_button = ttk.Button(toolbar, text="Open executable", command=self.open_file)
        self.open_button.pack(side=tk.LEFT)
        self.save_button = ttk.Button(toolbar, text="Save report", command=self.save_report, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=(8, 0))
        self.disassemble_button = ttk.Button(
            toolbar, text="Disassemble (Rizin)", command=self.disassemble, state=tk.DISABLED
        )
        self.disassemble_button.pack(side=tk.LEFT, padx=(8, 0))
        self.decompile_button = ttk.Button(
            toolbar, text="Decompile .NET (ILSpy)", command=self.decompile, state=tk.DISABLED
        )
        self.decompile_button.pack(side=tk.LEFT, padx=(8, 0))
        self.verify_signature_button = ttk.Button(
            toolbar, text="Verify signature", command=self.verify_signature, state=tk.DISABLED
        )
        self.verify_signature_button.pack(side=tk.LEFT, padx=(8, 0))
        self.sandbox_button = ttk.Button(
            toolbar, text="Import sandbox report", command=self.import_sandbox_report, state=tk.DISABLED
        )
        self.sandbox_button.pack(side=tk.LEFT, padx=(8, 0))
        self.compare_button = ttk.Button(toolbar, text="Compare...", command=self.compare_with, state=tk.DISABLED)
        self.compare_button.pack(side=tk.LEFT, padx=(8, 0))
        self.yara_button = ttk.Button(toolbar, text="YARA scan...", command=self.yara_scan, state=tk.DISABLED)
        self.yara_button.pack(side=tk.LEFT, padx=(8, 0))
        self._build_menus()

        self.status = tk.StringVar(
            value="Select an authorized .exe or .dll file. Analysis tools never execute the sample."
        )
        ttk.Label(self.root, textvariable=self.status, padding=(10, 0, 10, 8)).pack(fill=tk.X)

        # One tab per part of the report; tables sort by a header click and copy rows with Ctrl+C.
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        summary = self._tab("Summary")
        self.facts_table = self._table(summary, (("Property", 200), ("Value", 700)), height=11)
        self.findings_table = self._table(summary, (("Level", 70), ("Note (hints, not a verdict)", 830)))
        self.sections_table = self._table(
            self._tab("Sections"),
            (("Name", 90), ("RVA", 90), ("File offset", 90), ("Virtual size", 100), ("Raw size", 100),
             ("Entropy", 70), ("Flags", 260), ("SHA-256", 480)),
        )
        self.imports_table = self._table(
            self._tab("Imports"), (("Kind", 90), ("Functions", 90)), tree_heading="Library / function"
        )
        self.exports_table = self._table(
            self._tab("Exports"), (("Name", 360), ("Ordinal", 80), ("RVA", 100), ("Forwarder", 300))
        )
        self.resources_table = self._table(
            self._tab("Resources"),
            (("Name / value", 420), ("Language", 80), ("Size", 90), ("File offset", 100)),
            tree_heading="Type / version field",
        )
        self.security_table = self._table(self._tab("Security"), (("Property", 300), ("Value", 600)))
        self.dotnet_table = self._table(
            self._tab(".NET"), (("Value", 640),), tree_heading="Property / reference"
        )
        strings_tab = self._tab("Strings")
        filter_row = ttk.Frame(strings_tab, padding=(0, 4))
        filter_row.pack(fill=tk.X)
        ttk.Label(filter_row, text="Filter:").pack(side=tk.LEFT)
        self.strings_filter = tk.StringVar()
        self.strings_filter.trace_add("write", lambda *_: self._fill_strings())
        filter_entry = ttk.Entry(filter_row, textvariable=self.strings_filter, width=40)
        filter_entry.pack(side=tk.LEFT, padx=(6, 0))
        ttk.Label(filter_row, text="Kind:").pack(side=tk.LEFT, padx=(10, 0))
        self.strings_kind = tk.StringVar(value="all")
        kind_box = ttk.Combobox(
            filter_row, textvariable=self.strings_kind, state="readonly", width=12,
            values=("all", "notable") + triage.STRING_CATEGORIES,
        )
        kind_box.pack(side=tk.LEFT, padx=(6, 0))
        kind_box.bind("<<ComboboxSelected>>", lambda _event: self._fill_strings())
        self.strings_count = tk.StringVar()
        ttk.Label(filter_row, textvariable=self.strings_count).pack(side=tk.LEFT, padx=(10, 0))
        self.strings_table = self._table(strings_tab, (("Kind", 80), ("String", 900)))
        self.tools_output = self._text(self._tab("Tools"))
        self.output = self._text(self._tab("Full report"))
        self.root.bind("<Control-f>", lambda _event: self._focus_strings_filter(filter_entry))

    def _px(self, pixels: int) -> int:
        return round(pixels * self._scale)

    def _tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self.notebook, padding=4)
        self.notebook.add(frame, text=title)
        return frame

    def _table(self, parent, columns, tree_heading: str | None = None, height: int | None = None) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=height is None, pady=(0, 4))
        names = [name for name, _width in columns]
        tree = ttk.Treeview(
            frame, columns=names, show="tree headings" if tree_heading else "headings", selectmode="extended"
        )
        if height is not None:
            tree.configure(height=height)
        if tree_heading:
            self._tree_tables.add(str(tree))
            tree.heading("#0", text=tree_heading, command=lambda: self._sort(tree, "#0"))
            tree.column("#0", width=self._px(280), stretch=True)
        for name, width in columns:
            tree.heading(name, text=name, command=lambda column=name: self._sort(tree, column))
            tree.column(name, width=self._px(width), anchor=tk.W, stretch=True)
        vertical = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.bind("<Control-c>", lambda _event: self._copy_rows(tree))
        return tree

    def _text(self, parent) -> tk.Text:
        text = tk.Text(parent, wrap=tk.NONE, font=("Consolas", 10), state=tk.DISABLED)
        vertical = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=text.yview)
        horizontal = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        text.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return text

    def _sort(self, tree: ttk.Treeview, column: str) -> None:
        """Sorts the top-level rows by `column` (numbers and 0x values by value); a second click
        reverses. Child rows (functions, version fields) stay under their parent."""
        descending = self._sort_state.get(str(tree)) == (column, False)
        self._sort_state[str(tree)] = (column, descending)

        def value(item: str) -> str:
            return tree.item(item, "text") if column == "#0" else tree.set(item, column)

        items = sorted(tree.get_children(""), key=lambda item: sort_key(value(item)), reverse=descending)
        for index, item in enumerate(items):
            tree.move(item, "", index)

    def _copy_rows(self, tree: ttk.Treeview) -> None:
        rows = []
        for item in tree.selection():
            cells = ([tree.item(item, "text")] if str(tree) in self._tree_tables else []) + [
                str(value) for value in tree.item(item, "values")
            ]
            rows.append("\t".join(cells))
        if rows:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(rows))
            self.status.set(f"Copied {len(rows)} row(s).")

    def _focus_strings_filter(self, entry: ttk.Entry) -> None:
        self.notebook.select(entry.master.master)  # the Strings tab
        entry.focus_set()

    def _build_menus(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Open executable...", accelerator="Ctrl+O", command=self.open_file)
        self.recent_menu = tk.Menu(file_menu, tearoff=False)
        file_menu.add_cascade(label="Open recent", menu=self.recent_menu)
        file_menu.add_command(label="Analyze folder (batch)...", command=self.analyze_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Save report...", accelerator="Ctrl+S", command=self.save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=file_menu)
        view_menu = tk.Menu(menubar, tearoff=False)
        self.theme_choice = tk.StringVar(value=self._settings["theme"])
        for value, label in (("system", "Theme: as Windows"), ("light", "Theme: light"), ("dark", "Theme: dark")):
            view_menu.add_radiobutton(label=label, value=value, variable=self.theme_choice,
                                      command=lambda value=value: self.apply_theme(value))
        menubar.add_cascade(label="View", menu=view_menu)
        self.root.configure(menu=menubar)
        self.root.bind("<Control-o>", lambda _event: self.open_file())
        self.root.bind("<Control-s>", lambda _event: self.save_report())
        self._fill_recent_menu()

    def _fill_recent_menu(self) -> None:
        self.recent_menu.delete(0, tk.END)
        recent = self._settings["recent"]
        for path in recent:
            self.recent_menu.add_command(label=path, command=lambda path=path: self.open_file(path))
        if not recent:
            self.recent_menu.add_command(label="(none)", state=tk.DISABLED)

    def _analysis_buttons(self) -> tuple[ttk.Button, ...]:
        return (
            self.save_button, self.disassemble_button, self.decompile_button, self.verify_signature_button,
            self.sandbox_button, self.compare_button, self.yara_button,
        )

    def open_file(self, selected: str | None = None) -> None:
        if selected is None:
            selected = filedialog.askopenfilename(
                title="Choose an executable to inspect",
                filetypes=[("Windows executables", "*.exe *.dll *.sys"), ("All files", "*.*")],
            )
        if not selected:
            return
        path = Path(selected)
        self._settings["recent"] = settings.with_recent(self._settings["recent"], str(path))
        settings.save(self._settings)
        self._fill_recent_menu()
        self._analysis = None
        self._input_path = path
        self._extensions = {}
        for button in self._analysis_buttons():
            button.configure(state=tk.DISABLED)
        self.open_button.configure(state=tk.DISABLED)
        self.status.set(f"Reading {path.name} as data; it will not be executed...")
        threading.Thread(target=self._analyze_worker, args=(path,), daemon=True).start()

    def compare_with(self) -> None:
        if self._analysis is None:
            return
        selected = filedialog.askopenfilename(
            title="Compare with another version of this file",
            filetypes=[("Windows executables", "*.exe *.dll *.sys"), ("All files", "*.*")],
        )
        if selected:
            self._run_optional_tool("comparison", Path(selected))

    def yara_scan(self) -> None:
        if self._analysis is None:
            return
        selected = filedialog.askopenfilename(
            title="YARA rules file (Cancel to choose a folder of rules)",
            filetypes=[("YARA rules", "*.yar *.yara"), ("All files", "*.*")],
        ) or filedialog.askdirectory(title="Folder of YARA rules")
        if selected:
            self._run_optional_tool("yara", Path(selected))

    def analyze_folder(self) -> None:
        folder = filedialog.askdirectory(title="Folder of executables to analyze (batch)")
        if not folder:
            return
        output = filedialog.askdirectory(title="Where to write the reports and summary.csv")
        if not output:
            return
        self.open_button.configure(state=tk.DISABLED)
        self.status.set("Analyzing the folder; files are read as data and never executed...")
        threading.Thread(target=self._batch_worker, args=(Path(folder), Path(output)), daemon=True).start()

    def _batch_worker(self, folder: Path, output: Path) -> None:
        from .batch import run_batch

        def progress(index: int, total: int, path: Path) -> None:
            self.root.after(0, self.status.set, f"Batch: {index} of {total}: {path.name}")

        try:
            analysed, failed = run_batch(folder, output, on_file=progress)
            message = f"Batch done: {analysed} analysed, {failed} could not be analysed. See {output / 'summary.csv'}."
        except (ValueError, OSError) as exc:
            message = f"Batch failed: {exc}"
        self.root.after(0, self._batch_done, message)

    def _batch_done(self, message: str) -> None:
        self.open_button.configure(state=tk.NORMAL)
        self.status.set(message)

    def _analyze_worker(self, path: Path) -> None:
        try:
            self._results.put((path, analyze_file(path), None, None))
        except PEFormatError as exc:
            self._results.put((path, None, str(exc), None))
        except Exception as exc:
            self._results.put((path, None, f"Unexpected analysis error: {exc}", None))

    def _run_optional_tool(self, name: str, other: Path | None = None) -> None:
        if self._input_path is None:
            return
        path = self._input_path
        self.open_button.configure(state=tk.DISABLED)
        if name == "authenticode-verification":
            self.status.set("Checking the cached Windows trust policy; the sample will not be executed...")
        elif name == "comparison":
            self.status.set(f"Reading {other.name} as data to compare; it will not be executed...")
        else:
            self.status.set(f"Running {name} with a bounded time and output limit...")
        threading.Thread(target=self._tool_worker, args=(path, name, other), daemon=True).start()

    def _tool_worker(self, path: Path, name: str, other: Path | None = None) -> None:
        try:
            if name == "authenticode-verification":
                extension = {
                    "kind": "signature-verification",
                    "verification": verify_authenticode(path).to_dict(),
                }
            elif name == "comparison":
                from .compare import compare_analyses

                extension = {"kind": "comparison", "diff": compare_analyses(self._analysis, analyze_file(other))}
            elif name == "yara":
                from .yara_scan import matches_to_dict, scan_file

                extension = {"kind": "yara", "result": matches_to_dict(scan_file(path, other), other)}
            else:
                result = disassemble_native(path) if name == "native-disassembly" else decompile_dotnet(path)
                extension = {
                    "kind": "tool-output",
                    "tool": result.tool,
                    "output": result.output,
                    "truncated": result.truncated,
                }
            self._results.put((path, None, None, {name: extension}))
        except (OSError, ValueError, RuntimeError) as exc:
            self._results.put((path, None, str(exc), {}))

    def disassemble(self) -> None:
        self._run_optional_tool("native-disassembly")

    def decompile(self) -> None:
        self._run_optional_tool("dotnet-il")

    def verify_signature(self) -> None:
        self._run_optional_tool("authenticode-verification")

    def import_sandbox_report(self) -> None:
        if self._analysis is None or self._input_path is None:
            return
        selected = filedialog.askopenfilename(
            title="Import report exported by an isolated sandbox",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not selected:
            return
        try:
            report = load_sandbox_report(selected, self._analysis.sha256)
        except SandboxReportError as exc:
            messagebox.showerror("Could not import sandbox report", str(exc), parent=self.root)
            return
        self._extensions["sandbox-behavior"] = {
            "kind": "sandbox-report",
            "report": report.to_dict(),
        }
        self.status.set(f"Imported {len(report.events)} sandbox events.")
        self._render_current()

    def _poll_results(self) -> None:
        try:
            path, analysis, error, extensions = self._results.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_results)
            return
        self.open_button.configure(state=tk.NORMAL)
        if error:
            if analysis is None and not extensions and self._analysis is not None:
                self.status.set("Optional analysis failed.")
                messagebox.showerror("Analysis tool failed", error, parent=self.root)
            else:
                self._analysis = None
                self.status.set("Analysis failed.")
                self._clear_tables()
                self._fill_strings()
                self.findings_table.insert(
                    "", tk.END, values=("Check", f"Could not analyze {path.name}: {error}"), tags=(findings.WARN,)
                )
                self._show_text(f"Could not analyze {path.name}:\n\n{error}\n")
        else:
            if analysis is not None:
                self._analysis = analysis
                self._extensions = {}
                for button in self._analysis_buttons():
                    button.configure(state=tk.NORMAL)
                self.status.set(f"Analysis complete: {path.name}")
            if extensions:
                self._extensions.update(extensions)
                self.status.set(f"Additional analysis complete: {path.name}")
            self._render_current()
        self.root.after(100, self._poll_results)

    def _render_current(self) -> None:
        if self._analysis is None:
            return
        tools = self._format_extensions()
        self._fill_tables(self._analysis)
        self._set_text(
            self.tools_output,
            "\n".join(tools).lstrip("\n")
            or "Disassembly, .NET decompilation, signature verification and imported sandbox reports appear here.",
        )
        self._show_text("\n".join([self._format_report(self._analysis)] + tools))

    def _clear_tables(self) -> None:
        for tree in self._tables():
            tree.delete(*tree.get_children(""))
        self._set_text(self.tools_output, "")

    def _tables(self) -> tuple[ttk.Treeview, ...]:
        return (
            self.facts_table, self.findings_table, self.sections_table, self.imports_table,
            self.exports_table, self.resources_table, self.security_table, self.dotnet_table, self.strings_table,
        )

    def _fill_tables(self, analysis: Analysis) -> None:
        self._clear_tables()
        verification = self._extensions.get("authenticode-verification", {}).get("verification")
        security = analysis.security
        facts = [
            ("File", analysis.file_name),
            ("Size", f"{analysis.file_size:,} bytes"),
            ("SHA-256", analysis.sha256),
            ("SHA-1", analysis.sha1),
            ("MD5", analysis.md5),
            ("Imphash", analysis.imphash or "(no imports)"),
            ("Checksum", self._checksum_text(analysis)),
            ("Architecture", f"{analysis.architecture} ({analysis.pe_format})"),
            ("Subsystem", security.subsystem if security else ""),
            ("Timestamp (UTC)", analysis.timestamp_utc),
            ("Entry point RVA", f"0x{analysis.entry_point_rva:X}"),
            ("Image base", f"0x{analysis.image_base:X}"),
            ("Signature", "not checked (Verify signature)" if verification is None else
             " / ".join(str(part) for part in (verification["status"], verification.get("source"),
                                                verification.get("signer")) if part)),
        ]
        version = next((item.version_info for item in analysis.resources if item.version_info), {})
        for key in ("CompanyName", "ProductName", "FileDescription", "FileVersion", "OriginalFilename"):
            if key in version:
                facts.append((key, version[key]))
        pdb = next((item.pdb_path for item in analysis.debug_info if item.pdb_path), None)
        if pdb:
            facts.append(("PDB path", pdb))
        for row in facts:
            self.facts_table.insert("", tk.END, values=row)
        labels = {findings.WARN: "Check", findings.INFO: "Info", findings.OK: "OK"}
        for finding in findings.summary_findings(analysis, self._extensions):
            self.findings_table.insert("", tk.END, values=(labels[finding.level], finding.text), tags=(finding.level,))

        for section in analysis.sections:
            self.sections_table.insert("", tk.END, values=(
                section.name, f"0x{section.virtual_address:08X}", f"0x{section.raw_offset:08X}",
                f"{section.virtual_size:,}", f"{section.raw_size:,}", f"{section.entropy:.4f}",
                " ".join(section.flags), section.sha256,
            ))
        for kind, libraries in (("import", analysis.imports), ("delay-load", analysis.delay_imports)):
            for library in libraries:
                parent = self.imports_table.insert(
                    "", tk.END, text=library.library, values=(kind, len(library.functions))
                )
                for function in library.functions:
                    self.imports_table.insert(parent, tk.END, text=function, values=("", ""))
        for item in analysis.exports:
            self.exports_table.insert("", tk.END, values=(
                item.name, item.ordinal, f"0x{item.address_rva:X}", item.forwarder or "",
            ))
        for item in analysis.resources:
            kind = f"{item.type_name} ({item.type})" if item.type_name else item.type
            parent = self.resources_table.insert(
                "", tk.END, text=kind, values=(item.name, item.language, f"{item.size:,}", f"0x{item.raw_offset:X}")
            )
            for key, value in item.version_info.items():
                self.resources_table.insert(parent, tk.END, text=key, values=(value, "", "", ""))
        for row in self._security_rows(analysis):
            self.security_table.insert("", tk.END, values=row)
        self._fill_dotnet(analysis)
        self._fill_strings()

    @staticmethod
    def _checksum_text(analysis: Analysis) -> str:
        if not analysis.checksum_stored:
            return f"not set (computed 0x{analysis.checksum_computed:08X}; only drivers and system DLLs must set it)"
        if analysis.checksum_stored == analysis.checksum_computed:
            return f"0x{analysis.checksum_stored:08X} (matches the file)"
        return (f"0x{analysis.checksum_stored:08X} stored, 0x{analysis.checksum_computed:08X} computed: "
                "the file changed after linking")

    def _fill_dotnet(self, analysis: Analysis) -> None:
        table = self.dotnet_table
        metadata = analysis.dotnet
        if metadata is None:
            table.insert("", tk.END, text="Not a .NET assembly", values=("",))
            return
        if metadata.error:
            table.insert("", tk.END, text="Error", values=(metadata.error,))
        for key, value in (
            ("Assembly", f"{metadata.assembly_name or '?'} {metadata.assembly_version or ''}".strip()),
            ("Culture", metadata.assembly_culture or ""),
            ("Public key token", metadata.public_key_token or "(not strong-named)"),
            ("Module", metadata.module_name or ""),
            ("MVID", metadata.mvid or ""),
            ("Metadata version", metadata.runtime_version),
            ("CLR flags", ", ".join(metadata.flags) or "(none)"),
            ("ReadyToRun (precompiled)", "yes" if metadata.ready_to_run else "no"),
            ("Types / methods", f"{metadata.type_count:,} / {metadata.method_count:,}"),
        ):
            table.insert("", tk.END, text=key, values=(value,))
        references = table.insert("", tk.END, text=f"Assembly references ({len(metadata.references)})",
                                  values=("",), open=True)
        for reference in metadata.references:
            table.insert(references, tk.END, text=reference.name, values=(
                f"{reference.version}, culture {reference.culture}, token {reference.public_key_token or 'none'}",
            ))
        if metadata.pinvoke_imports:
            pinvoke = table.insert("", tk.END, text=f"P/Invoke imports ({len(metadata.pinvoke_imports)})",
                                   values=("native functions called from managed code",))
            for item in metadata.pinvoke_imports:
                table.insert(pinvoke, tk.END, text=item, values=("",))
        rows = table.insert("", tk.END, text="Metadata tables", values=("row counts",))
        for name, count in metadata.table_rows:
            table.insert(rows, tk.END, text=name, values=(f"{count:,}",))

    @staticmethod
    def _security_rows(analysis: Analysis) -> list[tuple[str, str]]:
        """The Security tab: the mitigation lines of the full report (minus the Rich header's
        entries), then the manifest, overlay, debug records and the Rich header, one fact per row."""
        rows: list[tuple[str, str]] = []
        security_lines = InspectorWindow._format_security(analysis)[3:]
        manifest_lines = InspectorWindow._format_manifest(analysis)[3:]
        for line in security_lines + manifest_lines:
            key, separator, value = line.partition(": ")
            if separator and not line.startswith(" "):
                rows.append((key, value))
        overlay = analysis.overlay
        if overlay is None:
            rows.append(("Overlay", "none"))
        else:
            rows.append(("Overlay", f"{overlay.size:,} bytes at 0x{overlay.offset:X}, entropy {overlay.entropy:.4f}"))
            if overlay.certificate_bytes:
                rows.append(("Overlay: signature", f"{overlay.certificate_bytes:,} bytes"))
            if overlay.container:
                rows.append(("Overlay: looks like", f"{overlay.container} (at 0x{overlay.container_offset:X})"))
            rows.append(("Overlay SHA-256", overlay.sha256))
        for item in analysis.debug_info:
            rows.append((f"Debug record: {item.kind_name or item.kind}", item.pdb_path or item.timestamp_utc))
        if analysis.security is not None:
            for entry in analysis.security.rich_header:
                rows.append(("Rich header: product / build", f"{entry.product_id} / {entry.build} x {entry.count} objects"))
        return rows

    def _fill_strings(self) -> None:
        if not hasattr(self, "strings_table"):
            return
        self.strings_table.delete(*self.strings_table.get_children(""))
        if self._analysis is None:
            self.strings_count.set("")
            return
        needle = self.strings_filter.get().strip().lower()
        kind = self.strings_kind.get()
        categories = self._analysis.string_categories or ("",) * len(self._analysis.strings)
        shown = [
            (category, value) for value, category in zip(self._analysis.strings, categories)
            if needle in value.lower()
            and (kind == "all" or (kind == "notable" and category) or kind == category)
        ]
        for category, value in shown:
            self.strings_table.insert("", tk.END, values=(category, value))
        self.strings_count.set(
            f"{len(shown):,} shown of {len(self._analysis.strings):,} kept "
            f"({self._analysis.total_strings_found:,} found)"
        )

    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", value)
        widget.configure(state=tk.DISABLED)

    def _format_extensions(self) -> list[str]:
        rendered: list[str] = []
        for name, result in self._extensions.items():
            if result["kind"] == "tool-output":
                warning = "\n[Output truncated at the configured size limit.]" if result["truncated"] else ""
                rendered.extend(
                    [
                        "",
                        f"{name.upper()} ({result['tool']})",
                        "=" * 72,
                        "Static tool output; the selected executable was not launched.",
                        result["output"],
                        warning,
                    ]
                )
            elif result["kind"] == "sandbox-report":
                rendered.append(self._format_sandbox_report(result["report"]))
            elif result["kind"] == "signature-verification":
                verification = result["verification"]
                rendered.extend(
                    [
                        "",
                        "AUTHENTICODE TRUST VERIFICATION",
                        "=" * 72,
                        f"Status: {verification['status']}",
                        f"Status code: {verification['status_code']}",
                    ]
                )
                for key, label in (
                    ("source", "Signature"),
                    ("signer", "Signer"),
                    ("issuer", "Issuer"),
                    ("catalog", "Catalog"),
                ):
                    if verification.get(key):
                        rendered.append(f"{label}: {verification[key]}")
                rendered.extend([verification["detail"], "A trusted signature is not a safety verdict."])
            elif result["kind"] == "comparison":
                from .compare import format_comparison

                rendered.append(format_comparison(result["diff"]))
            elif result["kind"] == "yara":
                from .yara_scan import format_matches

                rendered.append(format_matches(result["result"]))
        return rendered

    @staticmethod
    def _format_sandbox_report(report: dict[str, Any]) -> str:
        lines = [
            "",
            "IMPORTED SANDBOX BEHAVIOR REPORT",
            "=" * 72,
            "Imported data only. Binary Inspector did not execute the sample.",
            f"Source SHA-256: {report.get('source_sha256') or '(not provided)'}",
        ]
        if report.get("source_hash_matches") is False:
            lines.append("WARNING: This report hash does not match the analyzed executable.")
        elif report.get("source_hash_matches") is None:
            lines.append("WARNING: The report could not be matched to the analyzed executable.")
        events = report.get("events", [])
        lines.append(f"Events: {len(events)}")
        for event in events:
            lines.append(
                f"[{event['category']}] {event['action']} {event['target']}".rstrip()
            )
            if event["details"]:
                lines.append(f"  {event['details']}")
            if event["timestamp"]:
                lines.append(f"  Time: {event['timestamp']}")
        return "\n".join(lines)

    def _show_text(self, value: str) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", value)
        self.output.configure(state=tk.DISABLED)

    @staticmethod
    def _format_report(analysis: Analysis) -> str:
        lines = [
            "BINARY INSPECTOR - STATIC REPORT",
            "=" * 72,
            "This file was read as data and was NOT executed.",
            "Metadata is not a safety verdict; trust verification is optional.",
            "",
            f"File: {analysis.file_name}",
            f"Size: {analysis.file_size:,} bytes",
            f"SHA-256: {analysis.sha256}",
            f"SHA-1: {analysis.sha1}",
            f"MD5: {analysis.md5}",
            f"Imphash: {analysis.imphash or '(no imports)'}",
            f"Checksum: {InspectorWindow._checksum_text(analysis)}",
            f"Architecture: {analysis.architecture} ({analysis.pe_format})",
            f"Machine: 0x{analysis.machine:04X}",
            f"PE timestamp (UTC): {analysis.timestamp_utc}"
            + (" -- IN THE FUTURE" if analysis.timestamp_note == "in the future" else ""),
            f"Entry point RVA: 0x{analysis.entry_point_rva:X}",
            f"Image base: 0x{analysis.image_base:X}",
            f"Certificate table declared: {analysis.authenticode_table_declared}",
        ]
        lines.extend(InspectorWindow._format_security(analysis))
        lines.extend(["", "SECTIONS", "-" * 72])
        if analysis.sections:
            for section in analysis.sections:
                lines.append(
                    f"{section.name:<10} RVA=0x{section.virtual_address:08X} "
                    f"file=0x{section.raw_offset:08X} "
                    f"virtual={section.virtual_size:>10,} raw={section.raw_size:>10,} "
                    f"entropy={section.entropy:.4f} flags=0x{section.characteristics:08X}"
                )
                if section.flags:
                    lines.append(f"{'':<10} {' '.join(section.flags)}")
        else:
            lines.append("(none)")
        lines.extend(InspectorWindow._format_overlay(analysis))
        lines.extend(["", "IMPORTED DLLS AND FUNCTIONS", "-" * 72])
        if analysis.imports:
            for imported in analysis.imports:
                lines.append(f"{imported.library} ({len(imported.functions)} functions)")
                lines.extend(f"  {name}" for name in imported.functions)
        else:
            lines.append("(no imports found)")
        lines.extend(["", "EXPORTED SYMBOLS", "-" * 72])
        lines.extend(
            f"{item.name} (ordinal {item.ordinal}) -> "
            f"{item.forwarder or f'RVA 0x{item.address_rva:X}'}"
            for item in analysis.exports
        )
        if not analysis.exports:
            lines.append("(none)")
        lines.extend(["", "DELAY-LOADED IMPORTS", "-" * 72])
        for item in analysis.delay_imports:
            lines.append(f"{item.library} ({len(item.functions)} functions)")
            lines.extend(f"  {name}" for name in item.functions)
        if not analysis.delay_imports:
            lines.append("(none)")
        lines.extend(["", "DEBUG INFORMATION", "-" * 72])
        for item in analysis.debug_info:
            lines.append(f"{item.kind_name or f'Type {item.kind}'} (type {item.kind}); timestamp {item.timestamp_utc}")
            if item.pdb_path:
                lines.append(f"  PDB: {item.pdb_path}")
        if not analysis.debug_info:
            lines.append("(none)")
        lines.extend(["", "RESOURCES", "-" * 72])
        for item in analysis.resources:
            kind = f"{item.type_name} ({item.type})" if item.type_name else item.type
            lines.append(
                f"type={kind} name={item.name} language={item.language} size={item.size} "
                f"file=0x{item.raw_offset:X}"
            )
            lines.extend(f"  {key}: {value}" for key, value in item.version_info.items())
        if not analysis.resources:
            lines.append("(none)")
        lines.extend(InspectorWindow._format_manifest(analysis))
        lines.extend(["", "CLR METADATA", "-" * 72])
        if analysis.clr_info:
            lines.append(
                f"Runtime {analysis.clr_info.major_runtime_version}."
                f"{analysis.clr_info.minor_runtime_version}; "
                f"metadata RVA=0x{analysis.clr_info.metadata_rva:X}, "
                f"size={analysis.clr_info.metadata_size}; "
                f"flags=0x{analysis.clr_info.flags:X}; "
                f"entry point=0x{analysis.clr_info.entry_point_token:X}"
            )
        else:
            lines.append("(no CLR header)")
        metadata = analysis.dotnet
        if metadata is not None:
            lines.append(metadata.error or (
                f"Assembly {metadata.assembly_name} {metadata.assembly_version}, token "
                f"{metadata.public_key_token or 'none'}, metadata {metadata.runtime_version}, "
                f"{metadata.type_count} types, {metadata.method_count} methods"
                + ("; ReadyToRun" if metadata.ready_to_run else "")
            ))
            lines.extend(f"  references {item.name} {item.version}" for item in metadata.references)
            lines.extend(f"  P/Invoke {item}" for item in metadata.pinvoke_imports)
        lines.extend(["", "TOOLCHAIN AND IMPORT HINTS (pattern matches, not a verdict)", "-" * 72])
        lines.extend(f"Built with: {hint.name} ({hint.evidence})" for hint in analysis.toolchain_hints)
        for hint in analysis.api_hints:
            lines.append(f"Imports for {hint.behaviour}: {', '.join(hint.functions)}")
        if not analysis.toolchain_hints and not analysis.api_hints:
            lines.append("(none)")
        lines.extend(["", "DELAY-LOAD / RESOURCE DATA ARE UNTRUSTED FILE METADATA."])
        lines.extend(
            [
                "",
                f"PRINTABLE STRINGS (showing {len(analysis.strings)} of "
                f"{analysis.total_strings_found} detected)",
                "-" * 72,
            ]
        )
        lines.extend(analysis.strings or ["(none)"])
        return "\n".join(lines)

    @staticmethod
    def _format_security(analysis: Analysis) -> list[str]:
        security = analysis.security
        if security is None:
            return []

        def mark(value) -> str:
            return {True: "yes", False: "NO", None: "unknown"}.get(value, str(value))

        lines = [
            "",
            "SECURITY MITIGATIONS (from headers; not a safety verdict)",
            "-" * 72,
            f"Subsystem: {security.subsystem}",
            f"ASLR (dynamic base, relocations kept): {mark(security.aslr)}",
            "High-entropy ASLR: "
            + (mark(security.high_entropy_va) if analysis.pe_format == "PE32+" else "not applicable (32-bit)"),
            f"DEP / NX: {mark(security.dep)}",
            f"Control Flow Guard: {mark(security.control_flow_guard)}",
            f"CET shadow stack compatible: {mark(security.cet_shadow_stack)}",
            f"SafeSEH: {security.safe_seh}",
            f"Stack cookie (/GS): "
            + (mark(security.stack_cookie) if security.stack_cookie is not None else "unknown (no load configuration)"),
            f"Signature required to load (FORCE_INTEGRITY): {mark(security.force_integrity)}",
            f"DllCharacteristics: {', '.join(security.dll_characteristics) or '(none)'}",
            f"File characteristics: {', '.join(security.file_characteristics) or '(none)'}",
        ]
        if security.tls_callbacks:
            lines.append(
                "TLS callbacks (run before the entry point): "
                + ", ".join(f"RVA 0x{rva:X}" for rva in security.tls_callbacks)
            )
        if security.writable_executable_sections:
            lines.append(
                "Writable AND executable sections: " + ", ".join(security.writable_executable_sections)
            )
        if security.rich_header:
            lines.append(f"Rich header: {len(security.rich_header)} tool entries (product id / build x objects)")
            lines.extend(
                f"  {entry.product_id:>4} / {entry.build:>5} x {entry.count}" for entry in security.rich_header
            )
        else:
            lines.append("Rich header: none (not linked with Microsoft's linker, or removed)")
        return lines

    @staticmethod
    def _format_overlay(analysis: Analysis) -> list[str]:
        lines = ["", "OVERLAY (data after the last section)", "-" * 72]
        overlay = analysis.overlay
        if overlay is None:
            return lines + ["(none)"]
        lines.append(
            f"Offset 0x{overlay.offset:X}, {overlay.size:,} bytes, entropy {overlay.entropy:.4f}"
        )
        lines.append(f"SHA-256: {overlay.sha256}")
        if overlay.certificate_bytes:
            rest = overlay.size - overlay.certificate_bytes
            lines.append(
                f"Authenticode certificate table: {overlay.certificate_bytes:,} bytes"
                + (f"; {rest:,} other bytes" if rest else " (the whole overlay)")
            )
        if overlay.container:
            lines.append(
                f"Looks like: {overlay.container} (marker at 0x{overlay.container_offset:X}); a hint, not a verdict"
            )
        return lines

    @staticmethod
    def _format_manifest(analysis: Analysis) -> list[str]:
        manifest = analysis.manifest
        if manifest is None:
            return []
        lines = ["", "APPLICATION MANIFEST", "-" * 72]
        lines.append(f"Requested execution level: {manifest.execution_level or '(not stated: asInvoker)'}")
        if manifest.ui_access:
            lines.append("uiAccess: true (may drive higher-integrity windows)")
        if manifest.auto_elevate:
            lines.append("autoElevate: true")
        if manifest.dpi_awareness:
            lines.append(f"DPI awareness: {manifest.dpi_awareness}")
        if manifest.dependencies:
            lines.append("Dependent assemblies: " + ", ".join(manifest.dependencies))
        return lines

    def save_report(self) -> None:
        if self._analysis is None:
            return
        selected = filedialog.asksaveasfilename(
            title="Save static analysis report",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not selected:
            return
        try:
            report = self._analysis.to_dict()
            report["extended_analysis"] = self._extensions
            Path(selected).write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Could not save report", str(exc), parent=self.root)
            return
        self.status.set(f"Report saved: {selected}")


def _use_system_dpi() -> None:
    """Draw at the display's real resolution instead of letting Windows stretch a 96-DPI bitmap
    (blurry text on a scaled display). Must run before the first window is created."""
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
    except (AttributeError, OSError):
        pass  # not Windows, or Windows before 8.1


def run_gui() -> None:
    _use_system_dpi()
    root = tk.Tk()
    InspectorWindow(root)
    root.mainloop()
