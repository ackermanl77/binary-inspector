"""Triage details for the PE report: readable names for numeric codes, what the header timestamp
means, the overlay (data after the last section), the application manifest, and the security
mitigations (DllCharacteristics, load config, TLS callbacks, Rich header).

Everything here reads bytes already in memory; nothing is executed. Malformed structures raise
PEFormatError like the rest of the parser rather than being guessed at.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

MAX_TLS_CALLBACKS = 256
MAX_RICH_ENTRIES = 512
MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFEST_DEPENDENCIES = 64
# Container markers are searched for in this much of the overlay's start and end.
_CONTAINER_SCAN_BYTES = 1024 * 1024

RESOURCE_TYPES = {
    "1": "RT_CURSOR",
    "2": "RT_BITMAP",
    "3": "RT_ICON",
    "4": "RT_MENU",
    "5": "RT_DIALOG",
    "6": "RT_STRING",
    "7": "RT_FONTDIR",
    "8": "RT_FONT",
    "9": "RT_ACCELERATOR",
    "10": "RT_RCDATA",
    "11": "RT_MESSAGETABLE",
    "12": "RT_GROUP_CURSOR",
    "14": "RT_GROUP_ICON",
    "16": "RT_VERSION",
    "17": "RT_DLGINCLUDE",
    "19": "RT_PLUGPLAY",
    "20": "RT_VXD",
    "21": "RT_ANICURSOR",
    "22": "RT_ANIICON",
    "23": "RT_HTML",
    "24": "RT_MANIFEST",
}

DEBUG_TYPES = {
    1: "COFF",
    2: "CODEVIEW",
    3: "FPO",
    4: "MISC",
    5: "EXCEPTION",
    6: "FIXUP",
    7: "OMAP_TO_SRC",
    8: "OMAP_FROM_SRC",
    9: "BORLAND",
    11: "CLSID",
    12: "VC_FEATURE",
    13: "POGO",
    14: "ILTCG",
    15: "MPX",
    16: "REPRO",
    17: "EMBEDDED_PORTABLE_PDB",
    19: "PDBCHECKSUM",
    20: "EX_DLLCHARACTERISTICS",
}
DEBUG_REPRO = 16
DEBUG_EX_DLLCHARACTERISTICS = 20

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows console",
    5: "OS/2 console",
    7: "POSIX console",
    9: "Windows CE GUI",
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows boot application",
}

SECTION_FLAGS = (
    (0x00000020, "code"),
    (0x00000040, "initialized-data"),
    (0x00000080, "uninitialized-data"),
    (0x02000000, "discardable"),
    (0x10000000, "shared"),
    (0x20000000, "execute"),
    (0x40000000, "read"),
    (0x80000000, "write"),
)
_SECTION_EXECUTE = 0x20000000
_SECTION_WRITE = 0x80000000

DLL_CHARACTERISTICS = (
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
)
FILE_CHARACTERISTICS = (
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
)
_GUARD_CF_INSTRUMENTED = 0x00000100
_CET_COMPAT = 0x00000001


class PEFormatError(ValueError):
    """Raised when a file is malformed or is not a supported PE image."""


def flag_names(value: int, table) -> tuple[str, ...]:
    return tuple(name for bit, name in table if value & bit)


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0-8)."""
    import math

    length = len(data)
    if not length:
        return 0.0
    counts = (data.count(bytes((value,))) for value in range(256))
    return -sum((count / length) * math.log2(count / length) for count in counts if count) + 0.0


def describe_timestamp(value: int, reproducible: bool, now: datetime | None = None) -> tuple[str, str]:
    """(text for the report, note). A reproducible build stores a content hash in the TimeDateStamp
    fields, so it is not shown as a date."""
    if reproducible:
        return f"not a date (reproducible-build hash 0x{value:08X})", "reproducible-build hash"
    if value == 0:
        return "not set", "not set"
    try:
        moment = datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return "unavailable", ""
    now = now or datetime.now(timezone.utc)
    if moment > now + timedelta(days=1):
        return moment.isoformat(), "in the future"
    return moment.isoformat(), ""


# ---- overlay ----------------------------------------------------------------------------

@dataclass(frozen=True)
class Overlay:
    offset: int
    size: int
    sha256: str
    entropy: float
    certificate_bytes: int  # how much of the overlay is the Authenticode certificate table
    container: str | None  # a recognised format, as a hint
    container_offset: int | None


_CONTAINER_HEADS = (
    (b"MZ", "embedded PE executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"MSCF", "Microsoft Cabinet archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (e.g. MSI)"),
)
_CONTAINER_MARKERS = (
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller archive", "end"),
    (b"\xef\xbe\xad\xdeNullsoftInst", "NSIS installer data", "start"),
    (b"Inno Setup Setup Data", "Inno Setup installer data", "start"),
    (b"PK\x05\x06", "ZIP archive (central directory)", "end"),
)


def _container(data: bytes, start: int, end: int) -> tuple[str, int] | None:
    for magic, name in _CONTAINER_HEADS:
        if data.startswith(magic, start):
            return name, start
    head_end = min(end, start + _CONTAINER_SCAN_BYTES)
    tail_start = max(start, end - _CONTAINER_SCAN_BYTES)
    for marker, name, where in _CONTAINER_MARKERS:
        found = data.find(marker, start, head_end) if where == "start" else data.rfind(marker, tail_start, end)
        if found != -1:
            return name, found
    return None


def find_overlay(data: bytes, sections_end: int, cert_offset: int, cert_size: int) -> Overlay | None:
    """The bytes after the last section's raw data, if any."""
    if sections_end >= len(data):
        return None
    start, end = sections_end, len(data)
    certificate_bytes = 0
    if cert_size and cert_offset >= start:
        certificate_bytes = min(cert_size, end - cert_offset)
    # Look for a container in what isn't the signature: a signed installer's data comes before it.
    payload_end = cert_offset if certificate_bytes and cert_offset + cert_size >= end else end
    found = _container(data, start, payload_end) if payload_end > start else None
    blob = data[start:end]
    return Overlay(
        offset=start,
        size=end - start,
        sha256=hashlib.sha256(blob).hexdigest(),
        entropy=round(entropy(blob), 4),
        certificate_bytes=certificate_bytes,
        container=found[0] if found else None,
        container_offset=found[1] if found else None,
    )


# ---- manifest -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Manifest:
    execution_level: str | None  # asInvoker / highestAvailable / requireAdministrator
    ui_access: bool | None
    auto_elevate: bool | None
    dpi_awareness: str | None
    dependencies: tuple[str, ...]
    text: str


def _attribute(element: str, attribute: str, text: str) -> str | None:
    match = re.search(
        rf"<(?:\w+:)?{element}\b[^>]*?\b{attribute}\s*=\s*[\"']([^\"']*)[\"']", text, re.IGNORECASE
    )
    return match.group(1) if match else None


def _element_text(element: str, text: str) -> str | None:
    match = re.search(rf"<(?:\w+:)?{element}\b[^>]*>\s*([^<]*?)\s*<", text, re.IGNORECASE)
    return match.group(1) if match else None


def _boolean(value: str | None) -> bool | None:
    return None if value is None else value.strip().lower() == "true"


def parse_manifest(raw: bytes) -> Manifest:
    """The fields that matter for triage, read from the manifest text (no XML parser: the input is
    untrusted, and only a few attributes are needed)."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise PEFormatError(f"The manifest exceeded the {MAX_MANIFEST_BYTES // 1024} KiB parsing limit.")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    dependencies = []
    for block in re.findall(
        r"<(?:\w+:)?dependentAssembly\b.*?</(?:\w+:)?dependentAssembly>", text, re.IGNORECASE | re.DOTALL
    ):
        name = _attribute("assemblyIdentity", "name", block)
        if name and name not in dependencies:
            dependencies.append(name)
            if len(dependencies) >= MAX_MANIFEST_DEPENDENCIES:
                break
    return Manifest(
        execution_level=_attribute("requestedExecutionLevel", "level", text),
        ui_access=_boolean(_attribute("requestedExecutionLevel", "uiAccess", text)),
        auto_elevate=_boolean(_element_text("autoElevate", text)),
        dpi_awareness=_element_text("dpiAwareness", text) or _element_text("dpiAware", text),
        dependencies=tuple(dependencies),
        text=text,
    )


# ---- security mitigations -----------------------------------------------------------------

@dataclass(frozen=True)
class RichEntry:
    product_id: int
    build: int
    count: int


@dataclass(frozen=True)
class Security:
    subsystem: str
    dll_characteristics: tuple[str, ...]
    file_characteristics: tuple[str, ...]
    aslr: bool  # DYNAMIC_BASE with relocations kept
    high_entropy_va: bool
    dep: bool
    control_flow_guard: bool  # GUARD_CF and an instrumented load config
    cet_shadow_stack: bool
    safe_seh: str  # yes / no / no SEH / not applicable (64-bit) / not applicable (IL-only)
    stack_cookie: bool | None  # None: no load configuration to tell
    force_integrity: bool
    tls_callbacks: tuple[int, ...]  # RVAs; they run before the entry point
    writable_executable_sections: tuple[str, ...]
    rich_header: tuple[RichEntry, ...]


@dataclass(frozen=True)
class LoadConfig:
    security_cookie: int
    se_handler_table: int
    se_handler_count: int
    guard_flags: int


def parse_load_config(data: bytes, offset: int, directory_size: int, is64: bool) -> LoadConfig:
    """The load-config fields that show mitigations; fields beyond the structure's own Size are
    absent (an older linker) and read as zero."""
    if offset + 4 > len(data):
        raise PEFormatError("The load configuration directory is outside the file.")
    size = min(struct.unpack_from("<I", data, offset)[0], len(data) - offset)
    if is64:
        layout = {"cookie": (0x58, "<Q"), "seh_table": (0x60, "<Q"), "seh_count": (0x68, "<Q"), "guard": (0x90, "<I")}
    else:
        layout = {"cookie": (0x3C, "<I"), "seh_table": (0x40, "<I"), "seh_count": (0x44, "<I"), "guard": (0x58, "<I")}
    values = {}
    for key, (field, fmt) in layout.items():
        end = field + struct.calcsize(fmt)
        values[key] = struct.unpack_from(fmt, data, offset + field)[0] if end <= size else 0
    return LoadConfig(values["cookie"], values["seh_table"], values["seh_count"], values["guard"])


def parse_tls_callbacks(data: bytes, offset: int, is64: bool, image_base: int, rva_to_offset) -> tuple[int, ...]:
    """RVAs of the TLS callbacks (code the loader runs before the entry point)."""
    width = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    field = offset + 3 * width  # StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks
    if field + width > len(data):
        raise PEFormatError("The TLS directory is truncated.")
    callbacks_va = struct.unpack_from(fmt, data, field)[0]
    if not callbacks_va:
        return ()
    if callbacks_va < image_base:
        raise PEFormatError("The TLS callback table address is below the image base.")
    table = rva_to_offset(callbacks_va - image_base)
    result = []
    for index in range(MAX_TLS_CALLBACKS + 1):
        position = table + index * width
        if position + width > len(data):
            raise PEFormatError("The TLS callback table is truncated.")
        value = struct.unpack_from(fmt, data, position)[0]
        if not value:
            return tuple(result)
        if index == MAX_TLS_CALLBACKS:
            break
        result.append(value - image_base if value >= image_base else value)
    raise PEFormatError(f"The TLS callback table exceeded the limit of {MAX_TLS_CALLBACKS} entries.")


def parse_rich_header(data: bytes, pe_offset: int) -> tuple[RichEntry, ...]:
    """The linker's Rich header between the DOS stub and the PE header: which compiler and linker
    builds produced the objects (product id, build number, object count). Empty when absent."""
    rich = data.rfind(b"Rich", 0x40, pe_offset)
    if rich == -1 or rich + 8 > pe_offset:
        return ()
    key = struct.unpack_from("<I", data, rich + 4)[0]
    start = None
    position = rich - 4
    while position >= 0x40 and (rich - position) // 8 <= MAX_RICH_ENTRIES + 2:
        if struct.unpack_from("<I", data, position)[0] ^ key == 0x536E6144:  # "DanS"
            start = position
            break
        position -= 4
    if start is None:
        return ()
    entries = []
    for position in range(start + 16, rich, 8):
        comp_id, count = struct.unpack_from("<II", data, position)
        comp_id ^= key
        count ^= key
        entries.append(RichEntry(comp_id >> 16, comp_id & 0xFFFF, count))
    return tuple(entries)


def security_summary(
    *,
    subsystem: int,
    dll_characteristics: int,
    file_characteristics: int,
    is64: bool,
    il_only: bool,
    load_config: LoadConfig | None,
    ex_dll_characteristics: int,
    tls_callbacks: tuple[int, ...],
    sections,
    rich_header: tuple[RichEntry, ...],
) -> Security:
    relocations_kept = not file_characteristics & 0x0001
    if is64:
        safe_seh = "not applicable (64-bit)"
    elif il_only:
        safe_seh = "not applicable (IL-only)"
    elif dll_characteristics & 0x0400:
        safe_seh = "no SEH"
    elif load_config and load_config.se_handler_table and load_config.se_handler_count:
        safe_seh = "yes"
    else:
        safe_seh = "no"
    return Security(
        subsystem=SUBSYSTEMS.get(subsystem, f"Unknown ({subsystem})"),
        dll_characteristics=flag_names(dll_characteristics, DLL_CHARACTERISTICS),
        file_characteristics=flag_names(file_characteristics, FILE_CHARACTERISTICS),
        aslr=bool(dll_characteristics & 0x0040) and relocations_kept,
        high_entropy_va=is64 and bool(dll_characteristics & 0x0020) and bool(dll_characteristics & 0x0040),
        dep=bool(dll_characteristics & 0x0100),
        control_flow_guard=bool(dll_characteristics & 0x4000)
        and bool(load_config and load_config.guard_flags & _GUARD_CF_INSTRUMENTED),
        cet_shadow_stack=bool(ex_dll_characteristics & _CET_COMPAT),
        safe_seh=safe_seh,
        stack_cookie=None if load_config is None else bool(load_config.security_cookie),
        force_integrity=bool(dll_characteristics & 0x0080),
        tls_callbacks=tls_callbacks,
        writable_executable_sections=tuple(
            section.name
            for section in sections
            if section.characteristics & _SECTION_EXECUTE and section.characteristics & _SECTION_WRITE
        ),
        rich_header=rich_header,
    )
