"""Tkinter interface for safe, static PE inspection."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .external_tools import decompile_dotnet, disassemble_native
from .pe import Analysis, PEFormatError, analyze_file
from .sandbox_report import SandboxReportError, load_sandbox_report
from .signature import verify_authenticode


class InspectorWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Binary Inspector - Static PE Analysis")
        self.root.geometry("980x700")
        self._results: queue.Queue[
            tuple[Path, Analysis | None, str | None, dict[str, Any] | None]
        ] = queue.Queue()
        self._analysis: Analysis | None = None
        self._input_path: Path | None = None
        self._extensions: dict[str, dict[str, Any]] = {}
        self._build()
        self.root.after(100, self._poll_results)

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

        self.status = tk.StringVar(
            value="Select an authorized .exe or .dll file. Analysis tools never execute the sample."
        )
        ttk.Label(self.root, textvariable=self.status, padding=(10, 0, 10, 8)).pack(fill=tk.X)

        self.output = tk.Text(self.root, wrap=tk.NONE, font=("Consolas", 10), state=tk.DISABLED)
        vertical = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.output.yview)
        horizontal = ttk.Scrollbar(self.root, orient=tk.HORIZONTAL, command=self.output.xview)
        self.output.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0), pady=(0, 8))
        vertical.pack(side=tk.RIGHT, fill=tk.Y, pady=(0, 8))
        horizontal.pack(side=tk.BOTTOM, fill=tk.X, padx=(8, 0))

    def open_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Choose an executable to inspect",
            filetypes=[("Windows executables", "*.exe *.dll"), ("All files", "*.*")],
        )
        if not selected:
            return
        path = Path(selected)
        self._analysis = None
        self._input_path = path
        self._extensions = {}
        self.save_button.configure(state=tk.DISABLED)
        self.disassemble_button.configure(state=tk.DISABLED)
        self.decompile_button.configure(state=tk.DISABLED)
        self.verify_signature_button.configure(state=tk.DISABLED)
        self.sandbox_button.configure(state=tk.DISABLED)
        self.open_button.configure(state=tk.DISABLED)
        self.status.set(f"Reading {path.name} as data; it will not be executed...")
        threading.Thread(target=self._analyze_worker, args=(path,), daemon=True).start()

    def _analyze_worker(self, path: Path) -> None:
        try:
            self._results.put((path, analyze_file(path), None, None))
        except PEFormatError as exc:
            self._results.put((path, None, str(exc), None))
        except Exception as exc:
            self._results.put((path, None, f"Unexpected analysis error: {exc}", None))

    def _run_optional_tool(self, name: str) -> None:
        if self._input_path is None:
            return
        path = self._input_path
        self.open_button.configure(state=tk.DISABLED)
        if name == "authenticode-verification":
            self.status.set("Checking the cached Windows trust policy; the sample will not be executed...")
        else:
            self.status.set(f"Running {name} with a bounded time and output limit...")
        threading.Thread(target=self._tool_worker, args=(path, name), daemon=True).start()

    def _tool_worker(self, path: Path, name: str) -> None:
        try:
            if name == "authenticode-verification":
                extension = {
                    "kind": "signature-verification",
                    "verification": verify_authenticode(path).to_dict(),
                }
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
                self._show_text(f"Could not analyze {path.name}:\n\n{error}\n")
        else:
            if analysis is not None:
                self._analysis = analysis
                self._extensions = {}
                self.save_button.configure(state=tk.NORMAL)
                self.disassemble_button.configure(state=tk.NORMAL)
                self.decompile_button.configure(state=tk.NORMAL)
                self.verify_signature_button.configure(state=tk.NORMAL)
                self.sandbox_button.configure(state=tk.NORMAL)
                self.status.set(f"Analysis complete: {path.name}")
            if extensions:
                self._extensions.update(extensions)
                self.status.set(f"Additional analysis complete: {path.name}")
            self._render_current()
        self.root.after(100, self._poll_results)

    def _render_current(self) -> None:
        if self._analysis is None:
            return
        rendered = [self._format_report(self._analysis)]
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
        self._show_text("\n".join(rendered))

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


def run_gui() -> None:
    root = tk.Tk()
    InspectorWindow(root)
    root.mainloop()
