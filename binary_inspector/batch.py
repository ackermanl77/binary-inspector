"""Batch mode (F4): every PE file in a folder analysed (never executed), one JSON report each and a
summary.csv with a row per file, including the ones that could not be analysed."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Callable

from .pe import PEFormatError, analyze_file

PE_SUFFIXES = (".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".efi")
MAX_BATCH_FILES = 100_000
SUMMARY_COLUMNS = (
    "file", "sha256", "imphash", "architecture", "subsystem", "signed", "aslr", "dep", "cfg",
    "dotnet", "overlay", "toolchain", "import_behaviours", "notable_strings", "error",
)


def find_pe_files(folder: Path, recursive: bool) -> list[Path]:
    pattern = "**/*" if recursive else "*"
    found = sorted(
        path for path in folder.glob(pattern)
        if path.is_file() and path.suffix.lower() in PE_SUFFIXES
    )
    if len(found) > MAX_BATCH_FILES:
        raise ValueError(f"More than {MAX_BATCH_FILES:,} files; choose a smaller folder.")
    return found


def _overlay_summary(overlay) -> str:
    if overlay is None:
        return ""
    if overlay.container:
        return overlay.container
    if overlay.size == overlay.certificate_bytes:
        return "signature only"
    return f"{overlay.size} bytes"


def _report_name(path: Path, folder: Path, used: set[str]) -> str:
    """A unique, flat file name for a report: sub\\app.exe -> sub__app.exe.json."""
    base = "__".join(path.relative_to(folder).parts) + ".json"
    name, counter = base, 1
    while name.lower() in used:
        counter += 1
        name = f"{base[:-5]}.{counter}.json"
    used.add(name.lower())
    return name


def run_batch(
    folder: str | Path,
    output: str | Path,
    *,
    recursive: bool = False,
    verify_signatures: bool = False,
    on_file: Callable[[int, int, Path], None] | None = None,
) -> tuple[int, int]:
    """Analyses the folder's PE files into `output`; returns (analysed, failed)."""
    folder, output = Path(folder), Path(output)
    if not folder.is_dir():
        raise ValueError(f"{folder} is not a folder.")
    output.mkdir(parents=True, exist_ok=True)
    files = find_pe_files(folder, recursive)
    used: set[str] = {"summary.csv"}
    analysed = failed = 0
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as summary_file:
        summary = csv.DictWriter(summary_file, fieldnames=SUMMARY_COLUMNS)
        summary.writeheader()
        for index, path in enumerate(files, 1):
            if on_file:
                on_file(index, len(files), path)
            relative = str(path.relative_to(folder))
            try:
                analysis = analyze_file(path)
            except PEFormatError as exc:
                failed += 1
                summary.writerow({"file": relative, "error": str(exc)})
                continue
            report = analysis.to_dict()
            signed = ""
            if verify_signatures:
                from .signature import verify_authenticode

                verification = verify_authenticode(path)
                report["extended_analysis"] = {"authenticode_verification": verification.to_dict()}
                signed = verification.status + (f" ({verification.source})" if verification.source else "")
            (output / _report_name(path, folder, used)).write_text(
                json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
            )
            analysed += 1
            security = analysis.security
            summary.writerow({
                "file": relative,
                "sha256": analysis.sha256,
                "imphash": analysis.imphash,
                "architecture": f"{analysis.architecture} {analysis.pe_format}",
                "subsystem": security.subsystem if security else "",
                "signed": signed,
                "aslr": security.aslr if security else "",
                "dep": security.dep if security else "",
                "cfg": security.control_flow_guard if security else "",
                "dotnet": analysis.dotnet.assembly_name or "yes" if analysis.dotnet else "",
                "overlay": _overlay_summary(analysis.overlay),
                "toolchain": "; ".join(hint.name for hint in analysis.toolchain_hints),
                "import_behaviours": "; ".join(hint.behaviour for hint in analysis.api_hints),
                "notable_strings": sum(1 for category in analysis.string_categories if category),
                "error": "",
            })
    return analysed, failed
