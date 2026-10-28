"""Reading .NET metadata (B6): the assembly's identity, the assemblies and native DLLs it uses,
its P/Invoke imports and how big it is (ECMA-335 partition II, sections 22 and 24).

Only the metadata tables are read; no code is loaded. Obfuscators often damage metadata on
purpose, so a malformed table stops this part with a stated error (DotNetMetadata.error) instead
of failing the whole report; nothing is guessed.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass

MAX_STREAMS = 16
MAX_ROWS = 1 << 24
MAX_LISTED = 1000  # references, module refs and P/Invoke imports kept per list

CLR_FLAGS = (
    (0x00000001, "IL_ONLY"),
    (0x00000002, "32BIT_REQUIRED"),
    (0x00000004, "IL_LIBRARY"),
    (0x00000008, "STRONG_NAME_SIGNED"),
    (0x00000010, "NATIVE_ENTRYPOINT"),
    (0x00010000, "TRACK_DEBUG_DATA"),
    (0x00020000, "32BIT_PREFERRED"),
)

# Column kinds: an int is a fixed width; "s"/"g"/"b" index the #Strings/#GUID/#Blob heaps; ("t", n)
# indexes table n; ("c", name) is a coded index.
_SCHEMA: dict[int, tuple] = {
    0x00: (2, "s", "g", "g", "g"),  # Module
    0x01: (("c", "ResolutionScope"), "s", "s"),  # TypeRef
    0x02: (4, "s", "s", ("c", "TypeDefOrRef"), ("t", 0x04), ("t", 0x06)),  # TypeDef
    0x03: (("t", 0x04),),  # FieldPtr
    0x04: (2, "s", "b"),  # Field
    0x05: (("t", 0x06),),  # MethodPtr
    0x06: (4, 2, 2, "s", "b", ("t", 0x08)),  # MethodDef
    0x07: (("t", 0x08),),  # ParamPtr
    0x08: (2, 2, "s"),  # Param
    0x09: (("t", 0x02), ("c", "TypeDefOrRef")),  # InterfaceImpl
    0x0A: (("c", "MemberRefParent"), "s", "b"),  # MemberRef
    0x0B: (2, ("c", "HasConstant"), "b"),  # Constant
    0x0C: (("c", "HasCustomAttribute"), ("c", "CustomAttributeType"), "b"),  # CustomAttribute
    0x0D: (("c", "HasFieldMarshal"), "b"),  # FieldMarshal
    0x0E: (2, ("c", "HasDeclSecurity"), "b"),  # DeclSecurity
    0x0F: (2, 4, ("t", 0x02)),  # ClassLayout
    0x10: (4, ("t", 0x04)),  # FieldLayout
    0x11: ("b",),  # StandAloneSig
    0x12: (("t", 0x02), ("t", 0x14)),  # EventMap
    0x13: (("t", 0x14),),  # EventPtr
    0x14: (2, "s", ("c", "TypeDefOrRef")),  # Event
    0x15: (("t", 0x02), ("t", 0x17)),  # PropertyMap
    0x16: (("t", 0x17),),  # PropertyPtr
    0x17: (2, "s", "b"),  # Property
    0x18: (2, ("t", 0x06), ("c", "HasSemantics")),  # MethodSemantics
    0x19: (("t", 0x02), ("c", "MethodDefOrRef"), ("c", "MethodDefOrRef")),  # MethodImpl
    0x1A: ("s",),  # ModuleRef
    0x1B: ("b",),  # TypeSpec
    0x1C: (2, ("c", "MemberForwarded"), "s", ("t", 0x1A)),  # ImplMap
    0x1D: (4, ("t", 0x04)),  # FieldRVA
    0x1E: (4, 4),  # EncLog
    0x1F: (4,),  # EncMap
    0x20: (4, 2, 2, 2, 2, 4, "b", "s", "s"),  # Assembly
    0x21: (4,),  # AssemblyProcessor
    0x22: (4, 4, 4),  # AssemblyOS
    0x23: (2, 2, 2, 2, 4, "b", "s", "s", "b"),  # AssemblyRef
    0x24: (4, ("t", 0x23)),  # AssemblyRefProcessor
    0x25: (4, 4, 4, ("t", 0x23)),  # AssemblyRefOS
    0x26: (4, "s", "b"),  # File
    0x27: (4, 4, "s", "s", ("c", "Implementation")),  # ExportedType
    0x28: (4, 4, "s", ("c", "Implementation")),  # ManifestResource
    0x29: (("t", 0x02), ("t", 0x02)),  # NestedClass
    0x2A: (2, 2, ("c", "TypeOrMethodDef"), "s"),  # GenericParam
    0x2B: (("c", "MethodDefOrRef"), "b"),  # MethodSpec
    0x2C: (("t", 0x2A), ("c", "TypeDefOrRef")),  # GenericParamConstraint
}
_CODED: dict[str, tuple[int, tuple[int, ...]]] = {  # tag bits, tables (-1: unused tag)
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)),
    "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (5, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11,
                               0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B)),
    "HasFieldMarshal": (1, (0x04, 0x08)),
    "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)),
    "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)),
    "CustomAttributeType": (3, (-1, -1, 0x06, 0x0A, -1)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)),
    "TypeOrMethodDef": (1, (0x02, 0x06)),
}


class MetadataError(ValueError):
    pass


@dataclass(frozen=True)
class AssemblyReference:
    name: str
    version: str
    culture: str
    public_key_token: str


@dataclass(frozen=True)
class DotNetMetadata:
    runtime_version: str  # the metadata root's version string, e.g. v4.0.30319
    flags: tuple[str, ...]
    ready_to_run: bool
    assembly_name: str | None = None
    assembly_version: str | None = None
    assembly_culture: str | None = None
    public_key_token: str | None = None
    module_name: str | None = None
    mvid: str | None = None
    references: tuple[AssemblyReference, ...] = ()
    module_references: tuple[str, ...] = ()  # native DLLs named by P/Invoke
    pinvoke_imports: tuple[str, ...] = ()  # dll!function
    type_count: int = 0
    method_count: int = 0
    table_rows: tuple[tuple[str, int], ...] = ()
    error: str | None = None


_TABLE_NAMES = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x03: "FieldPtr", 0x04: "Field", 0x05: "MethodPtr",
    0x06: "MethodDef", 0x07: "ParamPtr", 0x08: "Param", 0x09: "InterfaceImpl", 0x0A: "MemberRef",
    0x0B: "Constant", 0x0C: "CustomAttribute", 0x0D: "FieldMarshal", 0x0E: "DeclSecurity",
    0x0F: "ClassLayout", 0x10: "FieldLayout", 0x11: "StandAloneSig", 0x12: "EventMap", 0x13: "EventPtr",
    0x14: "Event", 0x15: "PropertyMap", 0x16: "PropertyPtr", 0x17: "Property", 0x18: "MethodSemantics",
    0x19: "MethodImpl", 0x1A: "ModuleRef", 0x1B: "TypeSpec", 0x1C: "ImplMap", 0x1D: "FieldRVA",
    0x1E: "EncLog", 0x1F: "EncMap", 0x20: "Assembly", 0x21: "AssemblyProcessor", 0x22: "AssemblyOS",
    0x23: "AssemblyRef", 0x24: "AssemblyRefProcessor", 0x25: "AssemblyRefOS", 0x26: "File",
    0x27: "ExportedType", 0x28: "ManifestResource", 0x29: "NestedClass", 0x2A: "GenericParam",
    0x2B: "MethodSpec", 0x2C: "GenericParamConstraint",
}


def _u(fmt: str, data: bytes, offset: int):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise MetadataError("a metadata structure runs past its stream")
    return struct.unpack_from(fmt, data, offset)


class _Reader:
    def __init__(self, metadata: bytes):
        self.data = metadata
        if len(metadata) < 16 or _u("<I", metadata, 0)[0] != 0x424A5342:  # "BSJB"
            raise MetadataError("the metadata root signature (BSJB) is missing")
        length = _u("<I", metadata, 12)[0]
        if length > 255:
            raise MetadataError("the metadata version string is too long")
        self.version = metadata[16 : 16 + length].split(b"\0", 1)[0].decode("ascii", "replace")
        offset = 16 + ((length + 3) & ~3)
        stream_count = _u("<H", metadata, offset + 2)[0]
        if stream_count > MAX_STREAMS:
            raise MetadataError("too many metadata streams")
        offset += 4
        self.streams: dict[str, bytes] = {}
        for _ in range(stream_count):
            start, size = _u("<II", metadata, offset)
            end = metadata.find(b"\0", offset + 8, offset + 8 + 32)
            if end == -1:
                raise MetadataError("a metadata stream name is not terminated")
            name = metadata[offset + 8 : end].decode("ascii", "replace")
            offset = (end + 4) & ~3
            if start + size > len(metadata):
                raise MetadataError(f"the {name} stream runs past the metadata")
            self.streams.setdefault(name, metadata[start : start + size])
        self.tables_stream = self.streams.get("#~") or self.streams.get("#-")
        if self.tables_stream is None:
            raise MetadataError("there is no metadata table stream (#~)")

    def string(self, index: int) -> str:
        heap = self.streams.get("#Strings", b"")
        if index >= len(heap) and index:
            raise MetadataError("a #Strings index is out of range")
        end = heap.find(b"\0", index)
        return heap[index : end if end != -1 else len(heap)].decode("utf-8", "replace")

    def blob(self, index: int) -> bytes:
        heap = self.streams.get("#Blob", b"")
        if not index:
            return b""
        if index >= len(heap):
            raise MetadataError("a #Blob index is out of range")
        first = heap[index]
        if first & 0x80 == 0:
            size, start = first, index + 1
        elif first & 0xC0 == 0x80:
            size, start = ((first & 0x3F) << 8) | _u("B", heap, index + 1)[0], index + 2
        else:
            size = ((first & 0x1F) << 24) | (_u(">I", heap, index)[0] & 0xFFFFFF)
            start = index + 4
        if start + size > len(heap):
            raise MetadataError("a #Blob entry runs past its heap")
        return heap[start : start + size]

    def guid(self, index: int) -> str | None:
        heap = self.streams.get("#GUID", b"")
        if not index:
            return None
        start = (index - 1) * 16
        if start + 16 > len(heap):
            raise MetadataError("a #GUID index is out of range")
        return str(uuid.UUID(bytes_le=heap[start : start + 16]))


def _token(public_key: bytes) -> str:
    """The public key token: the last 8 bytes of the key's SHA-1, reversed."""
    return hashlib.sha1(public_key).digest()[-8:][::-1].hex() if public_key else ""


def read_metadata(metadata: bytes, flags: int, ready_to_run: bool) -> DotNetMetadata:
    flag_names = tuple(name for bit, name in CLR_FLAGS if flags & bit)
    try:
        return _read(metadata, flag_names, ready_to_run)
    except MetadataError as exc:
        version = ""
        if metadata[:4] == b"BSJB" and len(metadata) >= 16:
            length = min(struct.unpack_from("<I", metadata, 12)[0], 255)
            version = metadata[16 : 16 + length].split(b"\0", 1)[0].decode("ascii", "replace")
        return DotNetMetadata(version, flag_names, ready_to_run, error=f"Metadata could not be read: {exc}.")


def _read(metadata: bytes, flag_names: tuple[str, ...], ready_to_run: bool) -> DotNetMetadata:
    reader = _Reader(metadata)
    tables = reader.tables_stream
    heap_sizes = _u("B", tables, 6)[0]
    valid = _u("<Q", tables, 8)[0]
    offset = 24
    rows: dict[int, int] = {}
    for table in range(64):
        if valid >> table & 1:
            count = _u("<I", tables, offset)[0]
            if count > MAX_ROWS:
                raise MetadataError("a metadata table is implausibly large")
            rows[table] = count
            offset += 4
    if heap_sizes & 0x40:  # extra data after the row counts (some #- streams)
        offset += 4
    for table in rows:
        if table not in _SCHEMA:
            raise MetadataError(f"unknown metadata table 0x{table:02X}")
    string_width = 4 if heap_sizes & 1 else 2
    guid_width = 4 if heap_sizes & 2 else 2
    blob_width = 4 if heap_sizes & 4 else 2

    def width(kind) -> int:
        if isinstance(kind, int):
            return kind
        if kind == "s":
            return string_width
        if kind == "g":
            return guid_width
        if kind == "b":
            return blob_width
        if kind[0] == "t":
            return 2 if rows.get(kind[1], 0) < 1 << 16 else 4
        bits, targets = _CODED[kind[1]]
        largest = max(rows.get(table, 0) for table in targets if table >= 0)
        return 2 if largest < 1 << (16 - bits) else 4

    starts: dict[int, int] = {}
    layouts: dict[int, list[tuple[int, int]]] = {}
    for table in sorted(rows):
        columns = []
        position = 0
        for kind in _SCHEMA[table]:
            size = width(kind)
            columns.append((position, size))
            position += size
        layouts[table] = columns
        starts[table] = offset
        offset += position * rows[table]
        if offset > len(tables):
            raise MetadataError("the metadata tables run past their stream")

    def row(table: int, index: int) -> list[int]:
        base = starts[table] + index * sum(size for _, size in layouts[table])
        return [
            _u("<H" if size == 2 else "<I", tables, base + position)[0] if size in (2, 4) else 0
            for position, size in layouts[table]
        ]

    result: dict = {}
    if rows.get(0x00):
        module = row(0x00, 0)
        result["module_name"] = reader.string(module[1])
        result["mvid"] = reader.guid(module[2])
    if rows.get(0x20):
        _, major, minor, build, revision, _, key, name, culture = row(0x20, 0)
        result["assembly_name"] = reader.string(name)
        result["assembly_version"] = f"{major}.{minor}.{build}.{revision}"
        result["assembly_culture"] = reader.string(culture) or "neutral"
        result["public_key_token"] = _token(reader.blob(key)) or None
    references = []
    for index in range(min(rows.get(0x23, 0), MAX_LISTED)):
        major, minor, build, revision, ref_flags, key, name, culture, _ = row(0x23, index)
        key_bytes = reader.blob(key)
        token = _token(key_bytes) if ref_flags & 1 else key_bytes.hex()
        references.append(AssemblyReference(
            reader.string(name), f"{major}.{minor}.{build}.{revision}", reader.string(culture) or "neutral", token
        ))
    module_refs = [reader.string(row(0x1A, index)[0]) for index in range(min(rows.get(0x1A, 0), MAX_LISTED))]
    pinvoke = []
    for index in range(min(rows.get(0x1C, 0), MAX_LISTED)):
        _, _, name, scope = row(0x1C, index)
        library = module_refs[scope - 1] if 0 < scope <= len(module_refs) else "?"
        pinvoke.append(f"{library}!{reader.string(name)}")
    return DotNetMetadata(
        runtime_version=reader.version,
        flags=flag_names,
        ready_to_run=ready_to_run,
        references=tuple(references),
        module_references=tuple(module_refs),
        pinvoke_imports=tuple(pinvoke),
        type_count=rows.get(0x02, 0),
        method_count=rows.get(0x06, 0),
        table_rows=tuple((_TABLE_NAMES.get(table, f"0x{table:02X}"), count) for table, count in sorted(rows.items())),
        **result,
    )
