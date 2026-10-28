"""The Summary tab's notes: what in a report deserves a look first. These are hints drawn from the
headers, never a verdict; each says what was seen so it can be checked in the other tabs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .pe import Analysis

WARN = "warn"  # worth a closer look
INFO = "info"  # context
OK = "ok"  # a protection or check that is in place

HIGH_ENTROPY = 7.2  # bits per byte; compressed or encrypted data sits near 8


@dataclass(frozen=True)
class Finding:
    level: str
    text: str


def summary_findings(analysis: Analysis, extensions: dict[str, dict[str, Any]] | None = None) -> list[Finding]:
    found: list[Finding] = []
    add = lambda level, text: found.append(Finding(level, text))  # noqa: E731
    extensions = extensions or {}
    security = analysis.security
    managed = analysis.clr_info is not None

    verification = extensions.get("authenticode-verification", {}).get("verification")
    if verification is None:
        add(INFO, "Signature not checked yet (Verify signature)."
            + (" A certificate table is present." if analysis.authenticode_table_declared else ""))
    elif verification["status"] == "trusted":
        where = "a system catalog" if verification.get("source") == "catalog" else "an embedded signature"
        add(OK, f"Signed by {verification.get('signer') or 'an accepted signer'} through {where}.")
    elif verification["status"] == "unsigned":
        add(WARN, "Not signed: no embedded signature and no system catalog lists it.")
    elif verification["status"] == "untrusted":
        add(WARN, "The signature or its certificate chain was rejected by Windows.")
    else:
        add(INFO, "The signature could not be verified on this system.")

    if analysis.timestamp_note == "in the future":
        add(WARN, f"The build timestamp is in the future ({analysis.timestamp_utc}): set or forged by hand.")
    elif analysis.timestamp_note == "reproducible-build hash":
        add(INFO, "Reproducible build: the timestamp is a content hash, not a build date.")

    if managed:
        clr = analysis.clr_info
        add(INFO, f".NET assembly (CLR {clr.major_runtime_version}.{clr.minor_runtime_version})"
            + ("; IL only." if clr.flags & 0x1 else "; contains native code."))
    elif not analysis.imports and not analysis.delay_imports:
        add(WARN, "No imported functions: packed or loader-stub executables often look like this.")

    packed = [
        section.name for section in analysis.sections
        if section.entropy >= HIGH_ENTROPY and "execute" in section.flags
    ]
    if packed:
        add(WARN, f"High-entropy executable section(s): {', '.join(packed)} (compressed or encrypted code?).")

    if security is not None:
        if not security.aslr:
            add(WARN, "No ASLR: the image always loads at the same address.")
        if not security.dep:
            add(WARN, "No DEP/NX: data pages may be executable.")
        if security.writable_executable_sections:
            add(WARN, f"Writable and executable section(s): {', '.join(security.writable_executable_sections)}.")
        if not managed and not security.control_flow_guard:
            add(INFO, "Built without Control Flow Guard.")
        if security.tls_callbacks:
            add(INFO, f"{len(security.tls_callbacks)} TLS callback(s) run before the entry point.")
        if security.aslr and security.dep and (managed or security.control_flow_guard):
            add(OK, "ASLR, DEP" + ("" if managed else " and Control Flow Guard") + " are enabled.")

    overlay = analysis.overlay
    if overlay is not None:
        extra = overlay.size - overlay.certificate_bytes
        if overlay.container:
            add(INFO, f"Appended data looks like a {overlay.container} ({overlay.size:,} bytes after the sections).")
        elif extra > 0:
            add(INFO, f"{extra:,} bytes of appended data besides any signature (entropy {overlay.entropy:.2f}).")

    for hint in analysis.toolchain_hints:
        if hint.name in ("UPX packer", "VMProtect", "Themida / WinLicense", "ASPack", "MPRESS packer"):
            add(WARN, f"Packed or protected with {hint.name} ({hint.evidence}): the real code is hidden until run.")
        elif hint.name == ".NET":
            continue  # the CLR note above says so already
        elif overlay is None or hint.name != overlay.container:  # the overlay note names its container
            add(INFO, f"Built with {hint.name} ({hint.evidence}).")

    # LoadLibrary/GetProcAddress are in nearly every program; the other groups are worth a glance.
    behaviours = [hint.behaviour for hint in analysis.api_hints if hint.behaviour != "loading code at run time"]
    if behaviours:
        add(INFO, "Imports functions used for: " + ", ".join(behaviours) + " (common in ordinary programs too).")

    if analysis.checksum_stored and analysis.checksum_stored != analysis.checksum_computed:
        add(INFO, "The header checksum does not match the file: it was changed after linking.")
    notable = sum(1 for category in analysis.string_categories if category)
    if notable:
        add(INFO, f"{notable} notable string(s): URLs, addresses, paths, registry keys or encoded data (Strings tab).")
    if analysis.dotnet is not None and analysis.dotnet.error:
        add(WARN, f".NET metadata could not be read ({analysis.dotnet.error}); obfuscators damage it on purpose.")

    manifest = analysis.manifest
    if manifest is not None:
        if manifest.execution_level in ("requireAdministrator", "highestAvailable"):
            add(INFO, f"The manifest asks for elevation ({manifest.execution_level}).")
        if manifest.auto_elevate:
            add(INFO, "The manifest sets autoElevate (Windows components elevate without a prompt).")
        if manifest.ui_access:
            add(WARN, "The manifest sets uiAccess: it can drive windows of higher integrity.")
    return found
