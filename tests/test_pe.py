from __future__ import annotations

import random
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from binary_inspector import pe
from binary_inspector.pe import MAX_FILE_BYTES, PEFormatError, analyze_bytes, analyze_file
from binary_inspector.__main__ import main


def make_pe32(with_import: bool = True) -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    if with_import:
        struct.pack_into("<II", data, optional + 96 + 8, 0x1100, 40)

    section = optional + 0xE0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x300, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)

    if with_import:
        raw = 0x200
        struct.pack_into("<IIIII", data, raw + 0x100, 0x1140, 0, 0, 0x1128, 0x1150)
        struct.pack_into("<IIIII", data, raw + 0x114, 0, 0, 0, 0, 0)
        data[raw + 0x128 : raw + 0x128 + 13] = b"KERNEL32.dll\0"
        struct.pack_into("<II", data, raw + 0x140, 0x1160, 0)
        struct.pack_into("<II", data, raw + 0x150, 0x1160, 0)
        struct.pack_into("<H", data, raw + 0x160, 0)
        data[raw + 0x162 : raw + 0x162 + 12] = b"ExitProcess\0"
    data[0x240:0x24B] = b"hello world"
    wide_string = "Example".encode("utf-16le") + b"\0\0"
    data[0x250 : 0x250 + len(wide_string)] = wide_string
    return bytes(data)


def make_pe32plus() -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x300, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    return bytes(data)


def set_directory(data: bytearray, index: int, rva: int, size: int) -> None:
    directory_offset = 112 if struct.unpack_from("<H", data, 0x98)[0] == 0x20B else 96
    struct.pack_into("<II", data, 0x98 + directory_offset + index * 8, rva, size)


def make_version_block(key: str, value: bytes, value_type: int, children: bytes = b"") -> bytes:
    key_data = key.encode("utf-16le") + b"\0\0"
    block = bytearray(6) + key_data
    block.extend(bytes((-len(block)) % 4))
    block.extend(value)
    block.extend(bytes((-len(block)) % 4))
    block.extend(children)
    value_length = len(value) // 2 if value_type == 1 else len(value)
    struct.pack_into("<HHH", block, 0, len(block), value_length, value_type)
    return bytes(block)


def make_version_resource() -> bytes:
    version = make_version_block("FileVersion", "1.2.3\0".encode("utf-16le"), 1)
    table = make_version_block("040904B0", b"", 1, version)
    strings = make_version_block("StringFileInfo", b"", 1, table)
    return make_version_block("VS_VERSION_INFO", bytes(52), 0, strings)


def make_resource_pe() -> bytes:
    data = bytearray(make_pe32(False))
    set_directory(data, 2, 0x1100, 0x200)
    root = 0x300
    struct.pack_into("<HH", data, root + 12, 0, 1)
    struct.pack_into("<II", data, root + 16, 16, 0x80000018)
    struct.pack_into("<HH", data, root + 0x18 + 12, 0, 1)
    struct.pack_into("<II", data, root + 0x18 + 16, 1, 0x80000030)
    struct.pack_into("<HH", data, root + 0x30 + 12, 0, 1)
    struct.pack_into("<II", data, root + 0x30 + 16, 1033, 0x48)
    version = make_version_resource()
    struct.pack_into("<IIII", data, root + 0x48, 0x1180, len(version), 1200, 0)
    data[0x380 : 0x380 + len(version)] = version
    return bytes(data)


class PEAnalysisTests(unittest.TestCase):
    def test_self_test_exits_without_opening_gui(self):
        self.assertEqual(main(["--self-test"]), 0)

    def test_reads_architecture_sections_hash_and_imports(self):
        report = analyze_bytes(make_pe32(), "sample.exe")
        self.assertEqual(report.architecture, "x86")
        self.assertEqual(report.pe_format, "PE32")
        self.assertEqual(report.image_base, 0x400000)
        self.assertEqual(report.sections[0].name, ".rdata")
        self.assertEqual(report.imports[0].library, "kernel32.dll")
        self.assertEqual(report.imports[0].functions, ("ExitProcess",))
        self.assertEqual(len(report.sha256), 64)
        self.assertIn("hello world", report.strings)
        self.assertIn("Example", report.strings)
        self.assertFalse(report.authenticode_table_declared)

    def test_reports_pe_without_imports(self):
        report = analyze_bytes(make_pe32(with_import=False))
        self.assertEqual(report.imports, ())

    def test_reads_pe32_plus_architecture(self):
        report = analyze_bytes(make_pe32plus())
        self.assertEqual((report.architecture, report.pe_format), ("x64", "PE32+"))
        self.assertEqual(report.image_base, 0x140000000)

    def test_reads_pe32_plus_imports_with_64_bit_thunks(self):
        data = bytearray(make_pe32plus())
        set_directory(data, 1, 0x1100, 40)
        struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1128, 0x1150)
        data[0x328:0x335] = b"KERNEL32.dll\0"
        struct.pack_into("<QQ", data, 0x340, 0x8000000000000007, 0)
        report = analyze_bytes(bytes(data))
        self.assertEqual(report.imports[0].functions, ("ordinal_7",))

    def test_import_budget_applies_across_aliased_descriptors(self):
        data = bytearray(make_pe32())
        set_directory(data, 1, 0x1180, 60)
        struct.pack_into("<IIIII", data, 0x380, 0x1140, 0, 0, 0x1128, 0x1150)
        struct.pack_into("<IIIII", data, 0x394, 0x1140, 0, 0, 0x1128, 0x1150)
        struct.pack_into("<IIIII", data, 0x3A8, 0, 0, 0, 0, 0)
        with patch.object(pe, "MAX_TOTAL_IMPORTS", 1):
            with self.assertRaisesRegex(PEFormatError, "total import count"):
                analyze_bytes(bytes(data))

    def test_import_name_output_has_an_aggregate_byte_limit(self):
        with patch.object(pe, "MAX_TOTAL_IMPORT_NAME_BYTES", 1):
            with self.assertRaisesRegex(PEFormatError, "import-name output"):
                analyze_bytes(make_pe32())

    def test_rejects_directory_count_larger_than_optional_header(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<I", data, 0x98 + 92, 17)
        with self.assertRaisesRegex(PEFormatError, "more data directories"):
            analyze_bytes(bytes(data))

    def test_rejects_incomplete_data_directory_pair(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<II", data, 0x98 + 96 + 8, 0x1100, 0)
        with self.assertRaisesRegex(PEFormatError, "incomplete RVA/size pair"):
            analyze_bytes(bytes(data))

    def test_rejects_rvas_mapping_to_overlapping_sections(self):
        data = bytearray(make_pe32())
        struct.pack_into("<H", data, 0x84 + 2, 2)
        second = 0x178 + 40
        data[second : second + 8] = b".alias\0\0"
        struct.pack_into("<IIII", data, second + 8, 0x200, 0x1000, 0x100, 0x500)
        struct.pack_into("<I", data, second + 36, 0x40000040)
        with self.assertRaisesRegex(PEFormatError, "overlapping sections"):
            analyze_bytes(bytes(data))

    def test_rejects_import_table_without_descriptor_terminator(self):
        data = bytearray(make_pe32())
        set_directory(data, 1, 0x1100, 20)
        struct.pack_into("<I", data, 0x314, 1)
        with self.assertRaises(PEFormatError):
            analyze_bytes(bytes(data))

    def test_rejects_certificate_table_outside_file(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 4, 0x5F0, 0x20)
        with self.assertRaisesRegex(PEFormatError, "certificate table"):
            analyze_bytes(bytes(data))

    def test_reads_named_exports(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 0, 0x1100, 0x60)
        struct.pack_into("<IIHHIIIIIII", data, 0x300, 0, 0, 0, 0, 0, 7, 1, 1, 0x1140, 0x1144, 0x1148)
        struct.pack_into("<I", data, 0x340, 0x1200)
        struct.pack_into("<I", data, 0x344, 0x1160)
        struct.pack_into("<H", data, 0x348, 0)
        data[0x360:0x369] = b"Exported\0"
        report = analyze_bytes(bytes(data))
        self.assertEqual((report.exports[0].name, report.exports[0].ordinal), ("Exported", 7))
        self.assertEqual(report.exports[0].address_rva, 0x1200)
        struct.pack_into("<I", data, 0x340, 0x1150)
        data[0x350:0x35B] = b"OTHER.Func\0"
        forwarded = analyze_bytes(bytes(data)).exports[0]
        self.assertEqual(forwarded.forwarder, "OTHER.Func")

    def test_reads_delay_imports(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 13, 0x1100, 64)
        struct.pack_into("<IIIIIIII", data, 0x300, 1, 0x1170, 0, 0, 0x1140, 0, 0, 0)
        data[0x370:0x37A] = b"delay.dll\0"
        struct.pack_into("<II", data, 0x340, 0x1160, 0)
        struct.pack_into("<H", data, 0x360, 0)
        data[0x362:0x36C] = b"DelayFunc\0"
        report = analyze_bytes(bytes(data))
        self.assertEqual(report.delay_imports[0].library, "delay.dll")
        self.assertEqual(report.delay_imports[0].functions, ("DelayFunc",))

    def test_reads_codeview_pdb_path(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 6, 0x1100, 28)
        struct.pack_into("<IIHHIIII", data, 0x300, 0, 0, 0, 0, 2, 32, 0, 0x380)
        data[0x380:0x3A0] = b"RSDS" + bytes(16) + struct.pack("<I", 1) + b"app.pdb\0"
        report = analyze_bytes(bytes(data))
        self.assertEqual(report.debug_info[0].pdb_path, "app.pdb")

    def test_reads_version_resource_strings(self):
        report = analyze_bytes(make_resource_pe())
        version = next(item for item in report.resources if item.type == "16")
        self.assertEqual(version.language, "1033")
        self.assertEqual(version.version_info["FileVersion"], "1.2.3")

    def test_rejects_resource_directory_cycles(self):
        data = bytearray(make_resource_pe())
        struct.pack_into("<I", data, 0x300 + 16 + 4, 0x80000000)
        with self.assertRaisesRegex(PEFormatError, "cycle"):
            analyze_bytes(bytes(data))

    def test_json_and_desktop_report_include_metadata_sections(self):
        report = analyze_bytes(make_resource_pe())
        json_report = report.to_dict()
        self.assertIn("exports", json_report)
        self.assertIn("resources", json_report)
        from binary_inspector.gui import InspectorWindow

        rendered = InspectorWindow._format_report(report)
        headings = (
            "EXPORTED SYMBOLS",
            "DELAY-LOADED IMPORTS",
            "DEBUG INFORMATION",
            "RESOURCES",
            "CLR METADATA",
        )
        for heading in headings:
            self.assertIn(heading, rendered)

    def test_reads_clr_runtime_header(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 14, 0x1100, 72)
        struct.pack_into("<IHHII", data, 0x300, 72, 2, 5, 0x1148, 16)
        struct.pack_into("<II", data, 0x310, 1, 0x06000001)
        report = analyze_bytes(bytes(data))
        self.assertEqual(report.clr_info.major_runtime_version, 2)
        self.assertEqual(report.clr_info.metadata_size, 16)
        self.assertEqual(report.clr_info.entry_point_token, 0x06000001)

    def test_rejects_non_pe_and_truncated_headers(self):
        for payload in (b"not pe", b"MZ" + bytes(80), make_pe32()[:0x110]):
            with self.subTest(length=len(payload)), self.assertRaises(PEFormatError):
                analyze_bytes(payload)

    def test_rejects_invalid_pe_offset(self):
        payload = bytearray(make_pe32())
        struct.pack_into("<I", payload, 0x3C, 0xFFFFFFF0)
        with self.assertRaisesRegex(PEFormatError, "offset"):
            analyze_bytes(bytes(payload))

    def test_rejects_section_outside_file(self):
        payload = bytearray(make_pe32())
        section = 0x178
        struct.pack_into("<I", payload, section + 16, 0x1000)
        struct.pack_into("<I", payload, section + 20, 0x200)
        with self.assertRaisesRegex(PEFormatError, "extends beyond"):
            analyze_bytes(bytes(payload))

    def test_rejects_files_over_size_limit(self):
        with self.assertRaisesRegex(PEFormatError, "256 MiB"):
            analyze_bytes(bytes(MAX_FILE_BYTES + 1))

    def test_deterministic_header_mutations_return_reports_or_parse_errors(self):
        source = make_pe32()
        rng = random.Random(20261027)
        for case in range(128):
            data = bytearray(source)
            for _ in range(rng.randint(1, 4)):
                offset = rng.randrange(0, 0x200)
                data[offset] ^= rng.randrange(1, 256)
            try:
                report = analyze_bytes(bytes(data), f"mutated-{case}.exe")
            except PEFormatError:
                continue
            self.assertEqual(report.file_size, len(data))

    def test_analyze_file_uses_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.exe"
            path.write_bytes(make_pe32(with_import=False))
            self.assertEqual(analyze_file(path).file_name, "sample.exe")


if __name__ == "__main__":
    unittest.main()
