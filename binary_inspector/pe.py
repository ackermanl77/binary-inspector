"""Bounded, read-only parsing of Windows Portable Executable files."""

from __future__ import annotations

import hashlib
import json
import math
import os
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORT_DESCRIPTORS = 4096
MAX_THUNKS_PER_IMPORT = 65536
MAX_TOTAL_IMPORTS = 100000
MAX_TOTAL_IMPORT_NAME_BYTES = 16 * 1024 * 1024
MAX_TOTAL_METADATA_TEXT_BYTES = 16 * 1024 * 1024
MAX_VERSION_RESOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_VERSION_RESOURCE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_VERSION_FIELDS = 10000
MAX_EXPORTS = 10000
MAX_DELAY_IMPORTS = 4096
MAX_DEBUG_ENTRIES = 4096
MAX_RESOURCE_ENTRIES = 4096
MAX_RESOURCE_DEPTH = 8
MAX_VERSION_FIELDS = 256
MAX_STRINGS = 2000
MAX_STRING_LENGTH = 512
MIN_STRING_LENGTH = 4
_MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}


class PEFormatError(ValueError):
    """Raised when a file is malformed or is not a supported PE image."""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float


@dataclass(frozen=True)
class Import:
    library: str
    functions: tuple[str, ...]


@dataclass(frozen=True)
class Export:
    name: str
    ordinal: int
    address_rva: int
    forwarder: str | None


@dataclass(frozen=True)
class DelayImport:
    library: str
    functions: tuple[str, ...]


@dataclass(frozen=True)
class DebugInfo:
    kind: int
    timestamp_utc: str
    pdb_path: str | None


@dataclass(frozen=True)
class Resource:
    type: str
    name: str
    language: str
    size: int
    version_info: dict[str, str]


@dataclass(frozen=True)
class ClrInfo:
    major_runtime_version: int
    minor_runtime_version: int
    metadata_rva: int
    metadata_size: int
    flags: int
    entry_point_token: int


@dataclass(frozen=True)
class Analysis:
    file_name: str
    file_size: int
    sha256: str
    architecture: str
    machine: int
    pe_format: str
    timestamp_utc: str
    entry_point_rva: int
    image_base: int
    authenticode_table_declared: bool
    sections: tuple[Section, ...]
    imports: tuple[Import, ...]
    exports: tuple[Export, ...]
    delay_imports: tuple[DelayImport, ...]
    debug_info: tuple[DebugInfo, ...]
    resources: tuple[Resource, ...]
    clr_info: ClrInfo | None
    strings: tuple[str, ...]
    total_strings_found: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of this report."""
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=True)


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PEFormatError("The executable is truncated or contains an out-of-range structure.")
    return struct.unpack_from(fmt, data, offset)


def _cstring(data: bytes, offset: int, limit: int = 4096) -> str:
    if offset < 0 or offset >= len(data):
        raise PEFormatError("A PE string points outside the file.")
    end_limit = min(len(data), offset + limit)
    end = data.find(b"\0", offset, end_limit)
    if end == -1:
        raise PEFormatError("A PE string is not terminated within the allowed range.")
    return data[offset:end].decode("ascii", errors="replace")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts
        if count
    )


def _readable_strings(data: bytes) -> tuple[tuple[str, ...], int]:
    found: list[str] = []
    seen: set[str] = set()
    total = 0

    def add(value: str) -> None:
        nonlocal total
        value = value.strip()
        if len(value) < MIN_STRING_LENGTH:
            return
        total += 1
        if value not in seen and len(found) < MAX_STRINGS:
            seen.add(value)
            found.append(value[:MAX_STRING_LENGTH])

    start = None
    for index, value in enumerate(data):
        if 32 <= value <= 126:
            if start is None:
                start = index
        elif start is not None:
            add(data[start:index].decode("ascii", errors="ignore"))
            start = None
    if start is not None:
        add(data[start:].decode("ascii", errors="ignore"))

    for alignment in (0, 1):
        start = None
        index = alignment
        while index + 1 < len(data):
            low, high = data[index], data[index + 1]
            printable = high == 0 and 32 <= low <= 126
            if printable and start is None:
                start = index
            elif not printable and start is not None:
                raw = data[start:index]
                add(raw.decode("utf-16le", errors="ignore"))
                start = None
            index += 2
        if start is not None:
            add(data[start:index].decode("utf-16le", errors="ignore"))

    return tuple(found), total


class _PE:
    def __init__(self, data: bytes):
        self.data = data
        self.sections: list[Section] = []
        self.imports: list[Import] = []
        self._total_imports = 0
        self._total_import_name_bytes = 0
        self._metadata_text_bytes = 0
        self._version_resource_bytes = 0
        self._version_field_count = 0

    def _record_metadata_text(self, value: str) -> str:
        self._metadata_text_bytes += len(value.encode("utf-8", errors="replace"))
        if self._metadata_text_bytes > MAX_TOTAL_METADATA_TEXT_BYTES:
            raise PEFormatError(
                "The total metadata text exceeded the "
                f"{MAX_TOTAL_METADATA_TEXT_BYTES // (1024 * 1024)} MiB output limit."
            )
        return value

    def parse(self, file_name: str) -> Analysis:
        if len(self.data) < 64 or self.data[:2] != b"MZ":
            raise PEFormatError("This file does not have a valid DOS/PE header.")

        pe_offset = _unpack("<I", self.data, 0x3C)[0]
        if pe_offset < 64 or pe_offset + 24 > len(self.data):
            raise PEFormatError("The PE header offset is outside the file.")
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PEFormatError("The PE signature is missing.")

        coff_offset = pe_offset + 4
        machine, section_count, timestamp, _, _, optional_size, _ = _unpack(
            "<HHIIIHH", self.data, coff_offset
        )
        if section_count == 0 or section_count > MAX_SECTIONS:
            raise PEFormatError(f"The PE section count must be between 1 and {MAX_SECTIONS}.")

        optional_offset = coff_offset + 20
        optional_end = optional_offset + optional_size
        if optional_end > len(self.data) or optional_size < 2:
            raise PEFormatError("The optional header is truncated.")
        magic = _unpack("<H", self.data, optional_offset)[0]
        if magic == 0x10B:
            pe_format = "PE32"
            directory_offset = optional_offset + 96
            directory_count_offset = optional_offset + 92
            image_base = _unpack("<I", self.data, optional_offset + 28)[0]
            thunk_width = 4
        elif magic == 0x20B:
            pe_format = "PE32+"
            directory_offset = optional_offset + 112
            directory_count_offset = optional_offset + 108
            image_base = _unpack("<Q", self.data, optional_offset + 24)[0]
            thunk_width = 8
        else:
            raise PEFormatError(f"Unsupported PE optional-header magic: 0x{magic:04X}.")

        if optional_size < (96 if magic == 0x10B else 112):
            raise PEFormatError("The optional header is too small for this PE format.")

        entry_point = _unpack("<I", self.data, optional_offset + 16)[0]
        section_table = optional_end
        table_end = section_table + section_count * 40
        if table_end > len(self.data):
            raise PEFormatError("The section table is truncated.")

        size_of_headers = _unpack("<I", self.data, optional_offset + 60)[0]
        for index in range(section_count):
            offset = section_table + index * 40
            raw_name = self.data[offset : offset + 8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace") or f"section_{index}"
            virtual_size, virtual_address, raw_size, raw_offset = _unpack(
                "<IIII", self.data, offset + 8
            )
            characteristics = _unpack("<I", self.data, offset + 36)[0]
            if raw_size and (raw_offset > len(self.data) or raw_size > len(self.data) - raw_offset):
                raise PEFormatError(f"Section {name!r} extends beyond the end of the file.")
            raw = self.data[raw_offset : raw_offset + raw_size] if raw_size else b""
            self.sections.append(
                Section(
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                    characteristics=characteristics,
                    entropy=round(_entropy(raw), 4),
                )
            )

        def rva_to_offset(rva: int) -> int:
            if rva < size_of_headers and rva < len(self.data):
                return rva
            matches = []
            for idx in range(section_count):
                offset = section_table + idx * 40
                virtual_size, virtual_address, raw_size, raw_offset = _unpack(
                    "<IIII", self.data, offset + 8
                )
                span = max(virtual_size, raw_size)
                if virtual_address <= rva < virtual_address + span:
                    delta = rva - virtual_address
                    matches.append((delta, raw_size, raw_offset))
            if len(matches) > 1:
                raise PEFormatError(f"RVA 0x{rva:X} maps to overlapping sections.")
            if matches:
                delta, raw_size, raw_offset = matches[0]
                if delta >= raw_size:
                    raise PEFormatError("An RVA points to uninitialized section data.")
                file_offset = raw_offset + delta
                if file_offset >= len(self.data):
                    raise PEFormatError("An RVA points outside the file.")
                return file_offset
            raise PEFormatError(f"RVA 0x{rva:X} does not map to file data.")

        directory_count = _unpack("<I", self.data, directory_count_offset)[0]
        available_directories = max(0, (optional_end - directory_offset) // 8)
        if directory_count > available_directories:
            raise PEFormatError(
                "The optional header declares more data directories than it contains."
            )

        def data_directory(index: int) -> tuple[int, int]:
            if index >= directory_count or index >= available_directories:
                return (0, 0)
            return _unpack("<II", self.data, directory_offset + index * 8)

        for index in range(directory_count):
            address, size = data_directory(index)
            if bool(address) != bool(size):
                if index == 4:
                    raise PEFormatError("The certificate table has an incomplete file range.")
                raise PEFormatError(f"Data directory {index} has an incomplete RVA/size pair.")

        cert_offset, cert_size = data_directory(4)
        cert_declared = bool(cert_offset and cert_size)
        if cert_declared and (
            cert_offset > len(self.data) or cert_size > len(self.data) - cert_offset
        ):
            raise PEFormatError("The declared certificate table extends beyond the file.")

        import_rva, import_size = data_directory(1)
        if import_rva and import_size:
            self._parse_imports(import_rva, import_size, rva_to_offset, thunk_width)
        export_rva, export_size = data_directory(0)
        exports = (
            self._parse_exports(export_rva, export_size, rva_to_offset)
            if export_rva and export_size
            else []
        )
        delay_rva, delay_size = data_directory(13)
        delay_imports = (
            self._parse_delay_imports(delay_rva, delay_size, rva_to_offset, thunk_width, image_base)
            if delay_rva and delay_size
            else []
        )
        debug_rva, debug_size = data_directory(6)
        debug_info = (
            self._parse_debug(debug_rva, debug_size, rva_to_offset)
            if debug_rva and debug_size
            else []
        )
        resource_rva, resource_size = data_directory(2)
        resources = (
            self._parse_resources(resource_rva, resource_size, rva_to_offset)
            if resource_rva and resource_size
            else []
        )
        clr_rva, clr_size = data_directory(14)
        clr_info = (
            self._parse_clr(clr_rva, clr_size, rva_to_offset) if clr_rva and clr_size else None
        )

        strings, string_count = _readable_strings(self.data)
        try:
            timestamp_utc = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            timestamp_utc = "unavailable"
        return Analysis(
            file_name=file_name,
            file_size=len(self.data),
            sha256=hashlib.sha256(self.data).hexdigest(),
            architecture=_MACHINE_NAMES.get(machine, f"Unknown (0x{machine:04X})"),
            machine=machine,
            pe_format=pe_format,
            timestamp_utc=timestamp_utc,
            entry_point_rva=entry_point,
            image_base=image_base,
            authenticode_table_declared=cert_declared,
            sections=tuple(self.sections),
            imports=tuple(self.imports),
            exports=tuple(exports),
            delay_imports=tuple(delay_imports),
            debug_info=tuple(debug_info),
            resources=tuple(resources),
            clr_info=clr_info,
            strings=strings,
            total_strings_found=string_count,
        )

    def _parse_thunks(self, thunk_rva: int, rva_to_offset, thunk_width: int) -> tuple[str, ...]:
        ordinal_mask = 1 << (thunk_width * 8 - 1)
        thunk_offset = rva_to_offset(thunk_rva)
        functions: list[str] = []
        for thunk_index in range(MAX_THUNKS_PER_IMPORT):
            value = _unpack(
                "<I" if thunk_width == 4 else "<Q",
                self.data,
                thunk_offset + thunk_index * thunk_width,
            )[0]
            if value == 0:
                return tuple(functions)
            self._total_imports += 1
            if self._total_imports > MAX_TOTAL_IMPORTS:
                raise PEFormatError(
                    f"The total import count exceeded the parsing limit of {MAX_TOTAL_IMPORTS}."
                )
            if value & ordinal_mask:
                function = f"ordinal_{value & 0xFFFF}"
            else:
                import_name_offset = rva_to_offset(value)
                function = _cstring(self.data, import_name_offset + 2)
            self._total_import_name_bytes += len(function.encode("utf-8", errors="replace"))
            if self._total_import_name_bytes > MAX_TOTAL_IMPORT_NAME_BYTES:
                raise PEFormatError(
                    "The total import-name output exceeded the "
                    f"{MAX_TOTAL_IMPORT_NAME_BYTES // (1024 * 1024)} MiB parsing limit."
                )
            functions.append(function)
        raise PEFormatError("An import thunk exceeded the parsing limit.")

    def _parse_imports(
        self, import_rva: int, import_size: int, rva_to_offset, thunk_width: int
    ) -> None:
        if import_size % 20:
            raise PEFormatError(
                "The import directory size is not a multiple of its descriptor size."
            )
        descriptor_offset = rva_to_offset(import_rva)
        max_descriptors = min(MAX_IMPORT_DESCRIPTORS, import_size // 20)
        for descriptor_index in range(max_descriptors):
            offset = descriptor_offset + descriptor_index * 20
            fields = _unpack("<IIIII", self.data, offset)
            original_thunk, _, _, name_rva, first_thunk = fields
            if not any(fields):
                return
            thunk_rva = original_thunk or first_thunk
            if not thunk_rva or not name_rva:
                raise PEFormatError("An import descriptor is missing its name or thunk table.")
            library = _cstring(self.data, rva_to_offset(name_rva)).lower()
            library = self._record_metadata_text(library)
            functions = self._parse_thunks(thunk_rva, rva_to_offset, thunk_width)
            self.imports.append(Import(library=library, functions=functions))
        raise PEFormatError("The import table exceeded the descriptor parsing limit.")

    def _parse_exports(self, export_rva: int, export_size: int, rva_to_offset) -> list[Export]:
        if export_size < 40:
            raise PEFormatError("The export directory is truncated.")
        offset = rva_to_offset(export_rva)
        (
            _,
            timestamp,
            _,
            _,
            _,
            ordinal_base,
            function_count,
            name_count,
            functions_rva,
            names_rva,
            ordinals_rva,
        ) = _unpack("<IIHHIIIIIII", self.data, offset)
        if function_count > MAX_EXPORTS or name_count > MAX_EXPORTS:
            raise PEFormatError(f"The export count exceeded the parsing limit of {MAX_EXPORTS}.")
        if function_count == 0:
            if name_count:
                raise PEFormatError("The export directory has names but no function table.")
            return []
        if not functions_rva or (name_count and (not names_rva or not ordinals_rva)):
            raise PEFormatError("The export directory is missing a required address table.")
        functions_offset = rva_to_offset(functions_rva)
        names = [f"ordinal_{ordinal_base + index}" for index in range(function_count)]
        if name_count:
            names_offset = rva_to_offset(names_rva)
            ordinals_offset = rva_to_offset(ordinals_rva)
            for index in range(name_count):
                name_rva = _unpack("<I", self.data, names_offset + index * 4)[0]
                ordinal_index = _unpack("<H", self.data, ordinals_offset + index * 2)[0]
                if ordinal_index >= function_count:
                    raise PEFormatError("An export name has an out-of-range ordinal index.")
                names[ordinal_index] = self._record_metadata_text(
                    _cstring(self.data, rva_to_offset(name_rva))
                )
        export_end = export_rva + export_size
        exports = []
        for index, name in enumerate(names):
            address_rva = _unpack("<I", self.data, functions_offset + index * 4)[0]
            forwarder = None
            if export_rva <= address_rva < export_end:
                forwarder = _cstring(self.data, rva_to_offset(address_rva))
            exports.append(Export(name, ordinal_base + index, address_rva, forwarder))
        return exports

    @staticmethod
    def _address_to_rva(value: int, attributes: int, image_base: int) -> int:
        if attributes & 1:
            return value
        if value < image_base or value - image_base > 0xFFFFFFFF:
            raise PEFormatError("A delay-import VA cannot be converted to an RVA.")
        return value - image_base

    def _parse_delay_imports(
        self, delay_rva: int, delay_size: int, rva_to_offset, thunk_width: int, image_base: int
    ) -> list[DelayImport]:
        if delay_size % 32:
            raise PEFormatError(
                "The delay-import directory size is not a multiple of its descriptor size."
            )
        descriptor_offset = rva_to_offset(delay_rva)
        max_descriptors = min(MAX_DELAY_IMPORTS, delay_size // 32)
        results = []
        for index in range(max_descriptors):
            fields = _unpack("<IIIIIIII", self.data, descriptor_offset + index * 32)
            if not any(fields):
                return results
            attributes, name_value, _, _, int_value, _, _, _ = fields
            name_rva = self._address_to_rva(name_value, attributes, image_base)
            thunk_rva = self._address_to_rva(int_value, attributes, image_base)
            if not name_rva or not thunk_rva:
                raise PEFormatError("A delay-import descriptor is missing its name or thunk table.")
            library = _cstring(self.data, rva_to_offset(name_rva)).lower()
            functions = self._parse_thunks(thunk_rva, rva_to_offset, thunk_width)
            results.append(DelayImport(self._record_metadata_text(library), functions))
        raise PEFormatError("The delay-import table exceeded the descriptor parsing limit.")

    def _parse_debug(self, debug_rva: int, debug_size: int, rva_to_offset) -> list[DebugInfo]:
        if debug_size % 28:
            raise PEFormatError("The debug directory size is not a multiple of its entry size.")
        count = debug_size // 28
        if count > MAX_DEBUG_ENTRIES:
            raise PEFormatError(
                f"The debug entry count exceeded the parsing limit of {MAX_DEBUG_ENTRIES}."
            )
        offset = rva_to_offset(debug_rva)
        results = []
        for index in range(count):
            _, timestamp, _, _, kind, data_size, _, raw_pointer = _unpack(
                "<IIHHIIII", self.data, offset + index * 28
            )
            pdb_path = None
            if (
                data_size
                and raw_pointer <= len(self.data)
                and data_size <= len(self.data) - raw_pointer
            ):
                raw = self.data[raw_pointer : raw_pointer + data_size]
                if kind == 2 and raw.startswith((b"RSDS", b"NB10")):
                    header_size = 24 if raw.startswith(b"RSDS") else 16
                    if len(raw) >= header_size:
                        pdb_path = raw[header_size:].split(b"\0", 1)[0].decode(
                            "utf-8", errors="replace"
                        )
                        pdb_path = self._record_metadata_text(pdb_path)
            elif data_size:
                raise PEFormatError("A debug data record extends beyond the end of the file.")
            try:
                timestamp_utc = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                timestamp_utc = "unavailable"
            results.append(DebugInfo(kind, timestamp_utc, pdb_path))
        return results

    @staticmethod
    def _resource_id(data: bytes, root_offset: int, resource_end: int, value: int) -> str:
        if value & 0x80000000:
            offset = root_offset + (value & 0x7FFFFFFF)
            if offset < root_offset or offset + 2 > resource_end:
                raise PEFormatError("A resource name is outside its declared range.")
            length = _unpack("<H", data, offset)[0]
            if length > MAX_STRING_LENGTH:
                raise PEFormatError("A resource name exceeded the parsing limit.")
            if offset + 2 + length * 2 > resource_end:
                raise PEFormatError("A resource name is truncated.")
            raw = data[offset + 2 : offset + 2 + length * 2]
            return raw.decode("utf-16le", errors="replace")
        return str(value & 0xFFFF)

    @staticmethod
    def _version_strings(data: bytes) -> dict[str, str]:
        result: dict[str, str] = {}
        visited = 0

        def parse_block(start: int, limit: int, parents: tuple[str, ...], depth: int) -> int:
            nonlocal visited
            if depth > 16:
                raise PEFormatError("A version resource exceeded the nesting limit.")
            visited += 1
            if visited > MAX_VERSION_FIELDS * 4:
                raise PEFormatError("A version resource exceeded the block parsing limit.")
            if start + 6 > limit:
                return limit
            length, value_length, value_type = _unpack("<HHH", data, start)
            if length < 6 or start + length > limit:
                raise PEFormatError("A version resource block has an invalid length.")
            end = start + length
            cursor = start + 6
            key_end = data.find(b"\0\0", cursor, end - 1)
            if key_end == -1:
                raise PEFormatError("A version resource key is not terminated.")
            if (key_end - cursor) % 2:
                key_end += 1
            key = data[cursor:key_end].decode("utf-16le", errors="replace")
            cursor = (key_end + 2 + 3) & ~3
            value_bytes = value_length * 2 if value_type == 1 else value_length
            value_end = cursor + value_bytes
            if value_end > end:
                raise PEFormatError("A version resource value extends beyond its block.")
            if value_type == 1 and key and parents and "StringFileInfo" in parents:
                text = data[cursor:value_end].decode("utf-16le", errors="replace").rstrip("\0")
                if text and len(result) < MAX_VERSION_FIELDS:
                    result[key] = text[:MAX_STRING_LENGTH]
            cursor = (value_end + 3) & ~3
            path = parents + (key,)
            while cursor + 6 <= end:
                child_length = _unpack("<H", data, cursor)[0]
                if child_length == 0:
                    break
                previous = cursor
                cursor = parse_block(cursor, end, path, depth + 1)
                if cursor <= previous:
                    break
            return end

        if data:
            parse_block(0, len(data), (), 0)
        return result

    def _parse_resources(
        self, resource_rva: int, resource_size: int, rva_to_offset
    ) -> list[Resource]:
        root_offset = rva_to_offset(resource_rva)
        resource_end = root_offset + resource_size
        if resource_end > len(self.data):
            raise PEFormatError("The resource directory extends beyond the end of the file.")
        results: list[Resource] = []
        visited: set[int] = set()
        entry_count = 0

        def walk(directory_relative: int, path: tuple[str, ...], depth: int) -> None:
            nonlocal entry_count
            if depth > MAX_RESOURCE_DEPTH:
                raise PEFormatError("The resource directory exceeded the nesting limit.")
            if directory_relative in visited:
                raise PEFormatError("The resource directory contains a cycle.")
            visited.add(directory_relative)
            directory = root_offset + directory_relative
            if directory < root_offset or directory + 16 > resource_end:
                raise PEFormatError("A resource directory header is outside its declared range.")
            named, ids = _unpack("<HH", self.data, directory + 12)
            count = named + ids
            if count > MAX_RESOURCE_ENTRIES or len(visited) + count > MAX_RESOURCE_ENTRIES:
                raise PEFormatError("The resource entry count exceeded its parsing limit.")
            entries_offset = directory + 16
            if entries_offset + count * 8 > resource_end:
                raise PEFormatError("A resource directory entry list is truncated.")
            entry_count += count
            if entry_count > MAX_RESOURCE_ENTRIES:
                raise PEFormatError("The resource entry count exceeded its parsing limit.")
            for index in range(count):
                name_value, target_value = _unpack("<II", self.data, entries_offset + index * 8)
                name = self._resource_id(self.data, root_offset, resource_end, name_value)
                target_relative = target_value & 0x7FFFFFFF
                next_path = path + (name,)
                if target_value & 0x80000000:
                    walk(target_relative, next_path, depth + 1)
                    continue
                entry = root_offset + target_relative
                if entry < root_offset or entry + 16 > resource_end:
                    raise PEFormatError("A resource data entry is outside its declared range.")
                data_rva, size, _, _ = _unpack("<IIII", self.data, entry)
                data_offset = rva_to_offset(data_rva) if size else 0
                if size and (data_offset > len(self.data) or size > len(self.data) - data_offset):
                    raise PEFormatError("A resource payload extends beyond the end of the file.")
                resource_type = next_path[0] if next_path else "unknown"
                if resource_type in ("16", "VERSION"):
                    if size > MAX_VERSION_RESOURCE_BYTES:
                        raise PEFormatError("A version resource exceeded the 4 MiB parsing limit.")
                    self._version_resource_bytes += size
                    if self._version_resource_bytes > MAX_TOTAL_VERSION_RESOURCE_BYTES:
                        raise PEFormatError(
                            "Version resources exceeded the 16 MiB aggregate parsing limit."
                        )
                    version_data = self.data[data_offset : data_offset + size]
                    version_info = self._version_strings(version_data)
                    self._version_field_count += len(version_info)
                    if self._version_field_count > MAX_TOTAL_VERSION_FIELDS:
                        raise PEFormatError("Version resources exceeded the aggregate field limit.")
                    for key, value in version_info.items():
                        self._record_metadata_text(key)
                        self._record_metadata_text(value)
                else:
                    version_info = {}
                for item in next_path:
                    self._record_metadata_text(item)
                results.append(
                    Resource(
                        resource_type,
                        next_path[1] if len(next_path) > 1 else "",
                        next_path[2] if len(next_path) > 2 else "",
                        size,
                        version_info,
                    )
                )
                if len(results) > MAX_RESOURCE_ENTRIES:
                    raise PEFormatError("The resource entry count exceeded its parsing limit.")

        walk(0, (), 0)
        return results

    def _parse_clr(self, clr_rva: int, clr_size: int, rva_to_offset) -> ClrInfo:
        if clr_size < 72:
            raise PEFormatError("The CLR runtime header is truncated.")
        offset = rva_to_offset(clr_rva)
        header_size, major, minor = _unpack("<IHH", self.data, offset)
        if header_size < 72 or header_size > clr_size:
            raise PEFormatError("The CLR runtime header has an invalid size.")
        metadata_rva, metadata_size = _unpack("<II", self.data, offset + 8)
        flags, entry_point = _unpack("<II", self.data, offset + 16)
        if metadata_size:
            metadata_offset = rva_to_offset(metadata_rva)
            if metadata_offset > len(self.data) or metadata_size > len(self.data) - metadata_offset:
                raise PEFormatError(
                    "The CLR metadata directory extends beyond the end of the file."
                )
            if metadata_rva > 0xFFFFFFFF - metadata_size + 1:
                raise PEFormatError("The CLR metadata RVA range overflows.")
            rva_to_offset(metadata_rva + metadata_size - 1)
        return ClrInfo(major, minor, metadata_rva, metadata_size, flags, entry_point)


def analyze_bytes(data: bytes, file_name: str = "<memory>") -> Analysis:
    """Analyze PE bytes without executing or modifying them."""
    if len(data) > MAX_FILE_BYTES:
        raise PEFormatError(f"Files larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB are not supported.")
    return _PE(data).parse(file_name)


def analyze_file(path: str | os.PathLike[str]) -> Analysis:
    """Read and analyze one local file, rejecting files above the size limit."""
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise PEFormatError(f"Could not inspect the selected file: {exc}") from exc
    if size > MAX_FILE_BYTES:
        raise PEFormatError(f"Files larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB are not supported.")
    try:
        with file_path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise PEFormatError(f"Could not read the selected file: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise PEFormatError(f"Files larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB are not supported.")
    return analyze_bytes(data, file_path.name)
