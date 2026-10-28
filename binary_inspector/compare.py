"""Comparing two files (F3): what changed between a known-good binary and another version of it.
Both are analysed statically; the result lists what was added, removed or changed."""

from __future__ import annotations

from typing import Any

from .pe import Analysis

# Facts compared one to one: (label, how to read it from an analysis).
_FACTS = (
    ("SHA-256", lambda a: a.sha256),
    ("Size", lambda a: a.file_size),
    ("Architecture", lambda a: f"{a.architecture} ({a.pe_format})"),
    ("Timestamp", lambda a: a.timestamp_utc),
    ("Entry point RVA", lambda a: f"0x{a.entry_point_rva:X}"),
    ("Imphash", lambda a: a.imphash),
    ("Certificate table declared", lambda a: a.authenticode_table_declared),
    ("Overlay", lambda a: None if a.overlay is None else f"{a.overlay.size} bytes ({a.overlay.container or 'unrecognised'})"),
    (".NET assembly", lambda a: None if a.dotnet is None else f"{a.dotnet.assembly_name} {a.dotnet.assembly_version}"),
    ("Toolchain", lambda a: ", ".join(hint.name for hint in a.toolchain_hints)),
)
_MITIGATIONS = ("aslr", "high_entropy_va", "dep", "control_flow_guard", "cet_shadow_stack", "safe_seh",
                "stack_cookie", "force_integrity", "tls_callbacks", "writable_executable_sections")


def _imports(analysis: Analysis) -> set[str]:
    return {
        f"{library.library}!{function}"
        for library in analysis.imports + analysis.delay_imports
        for function in library.functions
    }


def _version(analysis: Analysis) -> dict[str, str]:
    return next((item.version_info for item in analysis.resources if item.version_info), {})


def compare_analyses(old: Analysis, new: Analysis) -> dict[str, Any]:
    """The differences from `old` to `new`, as JSON-ready data. Empty lists/dicts mean no change."""
    changed_facts = {}
    for label, read in _FACTS:
        before, after = read(old), read(new)
        if before != after:
            changed_facts[label] = {"old": before, "new": after}

    old_sections = {section.name: section for section in old.sections}
    new_sections = {section.name: section for section in new.sections}
    changed_sections = {}
    for name in old_sections.keys() & new_sections.keys():
        before, after = old_sections[name], new_sections[name]
        if before.sha256 != after.sha256 or before.characteristics != after.characteristics:
            changed_sections[name] = {
                "raw_size": [before.raw_size, after.raw_size],
                "entropy": [before.entropy, after.entropy],
                "flags": [" ".join(before.flags), " ".join(after.flags)],
            }

    old_imports, new_imports = _imports(old), _imports(new)
    old_exports = {item.name for item in old.exports}
    new_exports = {item.name for item in new.exports}
    old_version, new_version = _version(old), _version(new)
    version_changes = {
        key: {"old": old_version.get(key), "new": new_version.get(key)}
        for key in sorted(old_version.keys() | new_version.keys())
        if old_version.get(key) != new_version.get(key)
    }
    mitigation_changes = {}
    if old.security is not None and new.security is not None:
        for field in _MITIGATIONS:
            before, after = getattr(old.security, field), getattr(new.security, field)
            if before != after:
                mitigation_changes[field] = {"old": before, "new": after}
    old_behaviours = {hint.behaviour for hint in old.api_hints}
    new_behaviours = {hint.behaviour for hint in new.api_hints}
    return {
        "old": old.file_name,
        "new": new.file_name,
        "identical": old.sha256 == new.sha256,
        "facts": changed_facts,
        "sections_added": sorted(new_sections.keys() - old_sections.keys()),
        "sections_removed": sorted(old_sections.keys() - new_sections.keys()),
        "sections_changed": changed_sections,
        "imports_added": sorted(new_imports - old_imports),
        "imports_removed": sorted(old_imports - new_imports),
        "exports_added": sorted(new_exports - old_exports),
        "exports_removed": sorted(old_exports - new_exports),
        "version_info": version_changes,
        "mitigations": mitigation_changes,
        "import_behaviours_added": sorted(new_behaviours - old_behaviours),
        "import_behaviours_removed": sorted(old_behaviours - new_behaviours),
    }


def format_comparison(diff: dict[str, Any]) -> str:
    """The comparison as text for the desktop app's Tools tab."""
    lines = ["", f"COMPARISON: {diff['old']} -> {diff['new']}", "=" * 72]
    if diff["identical"]:
        return "\n".join(lines + ["The two files are identical (same SHA-256)."])
    for label, change in diff["facts"].items():
        lines.append(f"{label}: {change['old']} -> {change['new']}")
    for key, title in (
        ("sections_added", "Sections added"), ("sections_removed", "Sections removed"),
        ("imports_added", "Imports added"), ("imports_removed", "Imports removed"),
        ("exports_added", "Exports added"), ("exports_removed", "Exports removed"),
        ("import_behaviours_added", "Import behaviours added"),
        ("import_behaviours_removed", "Import behaviours removed"),
    ):
        if diff[key]:
            lines.append(f"{title} ({len(diff[key])}):")
            lines.extend(f"  {item}" for item in diff[key])
    for name, change in diff["sections_changed"].items():
        lines.append(
            f"Section {name} changed: raw size {change['raw_size'][0]:,} -> {change['raw_size'][1]:,}, "
            f"entropy {change['entropy'][0]:.4f} -> {change['entropy'][1]:.4f}, flags {change['flags'][0]} -> {change['flags'][1]}"
        )
    for key, change in diff["version_info"].items():
        lines.append(f"Version {key}: {change['old']} -> {change['new']}")
    for key, change in diff["mitigations"].items():
        lines.append(f"Mitigation {key}: {change['old']} -> {change['new']}")
    if len(lines) == 3:
        lines.append("Different contents, but none of the compared metadata changed.")
    return "\n".join(lines)
