"""Triage details on generated PE fixtures: timestamps, the overlay, the manifest, readable names
and the security mitigations (DllCharacteristics, load config, TLS callbacks, Rich header)."""

from __future__ import annotations

import struct
import unittest
from datetime import datetime, timezone

from binary_inspector import pe_details
from binary_inspector.pe import PEFormatError, analyze_bytes
from tests.test_pe import make_pe32, make_pe32plus, make_resource_pe, set_directory

# make_pe32(): optional header at 0x98, one section (.rdata) at RVA 0x1000 = file 0x200, 0x400 bytes.
_COFF_CHARACTERISTICS = 0x96
_SUBSYSTEM = 0x98 + 68
_DLL_CHARACTERISTICS = 0x98 + 70
_SECTION_CHARACTERISTICS = 0x98 + 0xE0 + 36


def _file(rva: int) -> int:
    return rva - 0x1000 + 0x200


class TimestampTests(unittest.TestCase):
    NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)

    def test_a_reproducible_build_hash_is_not_shown_as_a_date(self):
        text, note = pe_details.describe_timestamp(0x112F10A4, True, self.NOW)
        self.assertEqual(note, "reproducible-build hash")
        self.assertIn("0x112F10A4", text)
        self.assertNotIn("1979", text)

    def test_future_zero_and_ordinary_timestamps(self):
        future = int(datetime(2098, 7, 24, tzinfo=timezone.utc).timestamp())
        self.assertEqual(pe_details.describe_timestamp(future, False, self.NOW)[1], "in the future")
        self.assertEqual(pe_details.describe_timestamp(0, False, self.NOW), ("not set", "not set"))
        past = int(datetime(2024, 1, 2, tzinfo=timezone.utc).timestamp())
        self.assertEqual(pe_details.describe_timestamp(past, False, self.NOW), ("2024-01-02T00:00:00+00:00", ""))

    def test_a_repro_debug_record_marks_the_header_and_debug_timestamps(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<I", data, 0x88, 0xF1D1D06D)  # COFF TimeDateStamp
        set_directory(data, 6, 0x1100, 28)
        struct.pack_into("<IIHHIIII", data, _file(0x1100), 0, 0xF1D1D06D, 0, 0, 16, 0, 0, 0)
        report = analyze_bytes(bytes(data))
        self.assertEqual(report.timestamp_note, "reproducible-build hash")
        self.assertEqual(report.timestamp_raw, 0xF1D1D06D)
        self.assertEqual(report.debug_info[0].kind_name, "REPRO")
        self.assertTrue(report.debug_info[0].timestamp_utc.startswith("not a date"))


class OverlayTests(unittest.TestCase):
    def test_no_overlay_when_the_last_section_ends_the_file(self):
        self.assertIsNone(analyze_bytes(make_pe32()).overlay)

    def test_an_appended_zip_before_a_signature(self):
        base = make_pe32(False)
        zipped = b"PK\x03\x04" + bytes(0x7C)
        certificate = bytes(0x40)
        data = bytearray(base + zipped + certificate)
        set_directory(data, 4, len(base) + len(zipped), len(certificate))
        overlay = analyze_bytes(bytes(data)).overlay
        self.assertEqual((overlay.offset, overlay.size), (len(base), 0xC0))
        self.assertEqual(overlay.certificate_bytes, 0x40)
        self.assertEqual((overlay.container, overlay.container_offset), ("ZIP archive", len(base)))
        self.assertEqual(len(overlay.sha256), 64)

    def test_a_signature_alone_is_an_overlay_with_no_container(self):
        base = make_pe32(False)
        data = bytearray(base + bytes(0x40))
        set_directory(data, 4, len(base), 0x40)
        overlay = analyze_bytes(bytes(data)).overlay
        self.assertEqual((overlay.size, overlay.certificate_bytes, overlay.container), (0x40, 0x40, None))

    def test_a_pyinstaller_cookie_near_the_end(self):
        tail = bytes(range(256)) * 8 + b"MEI\x0c\x0b\x0a\x0b\x0e" + bytes(80)
        overlay = analyze_bytes(make_pe32(False) + tail).overlay
        self.assertEqual(overlay.container, "PyInstaller archive")
        self.assertGreater(overlay.entropy, 7.0)


class ManifestTests(unittest.TestCase):
    MANIFEST = b"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"/>
  </dependentAssembly></dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
    <requestedExecutionLevel level='requireAdministrator' uiAccess="false"/>
  </requestedPrivileges></security></trustInfo>
  <application><windowsSettings>
    <ws2:dpiAwareness xmlns:ws2="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</ws2:dpiAwareness>
    <autoElevate xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</autoElevate>
  </windowsSettings></application>
</assembly>"""

    def test_the_triage_fields_are_read(self):
        manifest = pe_details.parse_manifest(self.MANIFEST)
        self.assertEqual(manifest.execution_level, "requireAdministrator")
        self.assertIs(manifest.ui_access, False)
        self.assertIs(manifest.auto_elevate, True)
        self.assertEqual(manifest.dpi_awareness, "PerMonitorV2")
        self.assertEqual(manifest.dependencies, ("Microsoft.Windows.Common-Controls",))

    def test_utf16_and_missing_fields_and_the_size_limit(self):
        manifest = pe_details.parse_manifest("﻿<assembly/>".encode("utf-16"))
        self.assertEqual((manifest.execution_level, manifest.auto_elevate, manifest.dependencies), (None, None, ()))
        with self.assertRaises(PEFormatError):
            pe_details.parse_manifest(bytes(pe_details.MAX_MANIFEST_BYTES + 1))


class NameTests(unittest.TestCase):
    def test_sections_resources_and_debug_types_have_names_and_file_offsets(self):
        report = analyze_bytes(make_resource_pe())
        section = report.sections[0]
        self.assertEqual(section.raw_offset, 0x200)
        self.assertEqual(section.flags, ("initialized-data", "read"))
        version = next(item for item in report.resources if item.type == "16")
        self.assertEqual(version.type_name, "RT_VERSION")
        self.assertEqual(version.raw_offset, 0x380)

    def test_an_import_size_that_is_not_a_whole_number_of_descriptors(self):
        """MinGW ld sets the size to the whole .idata section; the loader ignores it."""
        data = bytearray(make_pe32())
        set_directory(data, 1, 0x1100, 30)
        self.assertEqual(analyze_bytes(bytes(data)).imports[0].library, "kernel32.dll")


class SecurityTests(unittest.TestCase):
    def test_header_flags(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<HH", data, _SUBSYSTEM, 3, 0x0040 | 0x0100 | 0x0400)
        report = analyze_bytes(bytes(data))
        security = report.security
        self.assertEqual(security.subsystem, "Windows console")
        self.assertEqual((security.aslr, security.dep, security.control_flow_guard), (True, True, False))
        self.assertEqual(security.safe_seh, "no SEH")
        self.assertIsNone(security.stack_cookie)  # no load configuration
        self.assertEqual(security.dll_characteristics, ("DYNAMIC_BASE", "NX_COMPAT", "NO_SEH"))

    def test_stripped_relocations_defeat_aslr(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<H", data, _DLL_CHARACTERISTICS, 0x0040)
        struct.pack_into("<H", data, _COFF_CHARACTERISTICS, 0x0103)
        security = analyze_bytes(bytes(data)).security
        self.assertFalse(security.aslr)
        self.assertIn("RELOCS_STRIPPED", security.file_characteristics)

    def test_load_config_gives_safeseh_gs_and_cfg(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<H", data, _DLL_CHARACTERISTICS, 0x0040 | 0x0100 | 0x4000)
        set_directory(data, 10, 0x1100, 0x5C)
        config = _file(0x1100)
        struct.pack_into("<I", data, config, 0x5C)  # Size
        struct.pack_into("<III", data, config + 0x3C, 0x401000, 0x401100, 2)  # cookie, SEH table, count
        struct.pack_into("<I", data, config + 0x58, 0x100)  # GuardFlags: CF_INSTRUMENTED
        security = analyze_bytes(bytes(data)).security
        self.assertEqual((security.safe_seh, security.stack_cookie, security.control_flow_guard), ("yes", True, True))

    def test_an_old_short_load_config_has_no_guard_fields(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<H", data, _DLL_CHARACTERISTICS, 0x4000)
        set_directory(data, 10, 0x1100, 0x48)
        struct.pack_into("<I", data, _file(0x1100), 0x48)  # Size stops before GuardFlags
        struct.pack_into("<I", data, _file(0x1100) + 0x58, 0x100)  # beyond Size: ignored
        self.assertFalse(analyze_bytes(bytes(data)).security.control_flow_guard)

    def test_64_bit_files_have_no_safeseh_and_can_have_high_entropy_aslr(self):
        data = bytearray(make_pe32plus())
        struct.pack_into("<H", data, 0x98 + 70, 0x0020 | 0x0040)
        security = analyze_bytes(bytes(data)).security
        self.assertEqual(security.safe_seh, "not applicable (64-bit)")
        self.assertTrue(security.high_entropy_va)

    def test_tls_callbacks_are_listed(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 9, 0x1180, 24)
        struct.pack_into("<IIII", data, _file(0x1180), 0, 0, 0x401200, 0x4011C0)
        struct.pack_into("<III", data, _file(0x11C0), 0x401010, 0x401020, 0)
        self.assertEqual(analyze_bytes(bytes(data)).security.tls_callbacks, (0x1010, 0x1020))

    def test_an_unterminated_tls_callback_table_is_an_error(self):
        data = bytearray(make_pe32(False))
        set_directory(data, 9, 0x1180, 24)
        struct.pack_into("<IIII", data, _file(0x1180), 0, 0, 0, 0x4011C0)
        for index in range((0x600 - _file(0x11C0)) // 4):
            struct.pack_into("<I", data, _file(0x11C0) + index * 4, 0x401010)
        with self.assertRaises(PEFormatError):
            analyze_bytes(bytes(data))

    def test_writable_and_executable_sections_are_flagged(self):
        data = bytearray(make_pe32(False))
        struct.pack_into("<I", data, _SECTION_CHARACTERISTICS, 0xE0000020)
        self.assertEqual(analyze_bytes(bytes(data)).security.writable_executable_sections, (".rdata",))

    def test_the_rich_header_is_decoded(self):
        data = bytearray(make_pe32(False))
        key = 0x12345678
        words = [0x536E6144, 0, 0, 0, (259 << 16) | 33145, 7, (1 << 16) | 0, 1402]
        for index, word in enumerate(words):
            struct.pack_into("<I", data, 0x40 + index * 4, word ^ key)
        data[0x60:0x64] = b"Rich"
        struct.pack_into("<I", data, 0x64, key)
        entries = analyze_bytes(bytes(data)).security.rich_header
        self.assertEqual([(e.product_id, e.build, e.count) for e in entries], [(259, 33145, 7), (1, 0, 1402)])

    def test_the_desktop_report_shows_the_new_sections(self):
        from binary_inspector.gui import InspectorWindow

        data = bytearray(make_resource_pe())
        rendered = InspectorWindow._format_report(analyze_bytes(bytes(data) + b"PK\x03\x04" + bytes(60)))
        for text in ("SECURITY MITIGATIONS", "OVERLAY", "ZIP archive", "RT_VERSION (16)", "file=0x00000200"):
            self.assertIn(text, rendered)


if __name__ == "__main__":
    unittest.main()
