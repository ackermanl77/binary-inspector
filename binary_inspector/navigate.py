"""Addresses in a PE file for the GUI's Go to and Hex views (UI3, UI4): parse what the user typed,
convert between RVA, virtual address and file offset with the section table, and format bytes as
a hex dump. No Tk here, so it is testable on its own."""
from __future__ import annotations

from dataclasses import dataclass

from .pe import Analysis, Section

HEX_BYTES_PER_LINE = 16
HEX_PAGE_BYTES = 4096  # what the Hex tab shows at once (read from the file in chunks this size)

KINDS = ("rva", "offset", "va")


@dataclass(frozen=True)
class Location:
    rva: int | None
    offset: int | None
    section: str  # "" for the headers, "(none)" when no section maps it


def parse_address(text: str) -> int:
    """Hex by default ("1A2B", "0x1A2B", "1A2Bh"); "#123" is decimal. Raises ValueError."""
    value = text.strip().replace("_", "").replace("`", "")
    if not value:
        raise ValueError("Type an address.")
    if value.startswith("#"):
        return int(value[1:], 10)
    if value.lower().endswith("h"):
        value = value[:-1]
    number = int(value, 16)
    if number < 0:
        raise ValueError("Addresses can't be negative.")
    return number


def _headers_end(analysis: Analysis) -> int:
    raw = [s.raw_offset for s in analysis.sections if s.raw_size]
    return min(raw) if raw else analysis.file_size


def _section_for_rva(analysis: Analysis, rva: int) -> Section | None:
    for section in analysis.sections:
        if section.virtual_address <= rva < section.virtual_address + max(section.virtual_size, section.raw_size):
            return section
    return None


def _section_for_offset(analysis: Analysis, offset: int) -> Section | None:
    for section in analysis.sections:
        if section.raw_size and section.raw_offset <= offset < section.raw_offset + section.raw_size:
            return section
    return None


def locate(analysis: Analysis, value: int, kind: str) -> Location:
    """Where `value` (an RVA, a file offset, or a virtual address) is, in the other terms. A part of
    a section that has no bytes in the file (virtual size past its raw size) has no offset."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    if kind == "va":
        if value < analysis.image_base:
            raise ValueError(f"0x{value:X} is below the image base 0x{analysis.image_base:X}.")
        value, kind = value - analysis.image_base, "rva"
    headers_end = _headers_end(analysis)
    if kind == "rva":
        section = _section_for_rva(analysis, value)
        if section is None:
            if value < headers_end:
                return Location(rva=value, offset=value, section="")
            return Location(rva=value, offset=None, section="(none)")
        delta = value - section.virtual_address
        offset = section.raw_offset + delta if delta < section.raw_size else None
        return Location(rva=value, offset=offset, section=section.name)
    if value >= analysis.file_size:
        raise ValueError(f"0x{value:X} is past the end of the file (0x{analysis.file_size:X} bytes).")
    section = _section_for_offset(analysis, value)
    if section is None:
        if value < headers_end:
            return Location(rva=value, offset=value, section="")
        return Location(rva=None, offset=value, section="(none)")  # overlay or slack
    return Location(rva=section.virtual_address + value - section.raw_offset, offset=value, section=section.name)


def describe(location: Location, image_base: int) -> str:
    parts = []
    if location.rva is not None:
        parts.append(f"RVA 0x{location.rva:X} (VA 0x{image_base + location.rva:X})")
    parts.append(f"file offset 0x{location.offset:X}" if location.offset is not None else "no bytes in the file")
    where = {"": "in the headers", "(none)": "outside every section"}.get(location.section, f"in {location.section}")
    return ", ".join(parts) + f", {where}"


def page_start(offset: int) -> int:
    return offset - offset % HEX_PAGE_BYTES


def hex_lines(data: bytes, start: int) -> list[str]:
    """`data` (read from file offset `start`) as hex-dump lines: offset, 16 bytes, printable ASCII."""
    lines = []
    for index in range(0, len(data), HEX_BYTES_PER_LINE):
        chunk = data[index:index + HEX_BYTES_PER_LINE]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        hex_part = hex_part[:23] + " " + hex_part[23:] if len(chunk) > 8 else hex_part
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{start + index:08X}  {hex_part:<48}  {text}")
    return lines
