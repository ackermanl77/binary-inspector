"""Hashes and checksum (B9), string categories (F5), import behaviour hints (F1), toolchain hints
(B7), .NET metadata (B6), comparing files (F3), batch mode (F4), YARA (F2) and the app's settings
-- on generated fixtures (and real system files where noted, skipped if absent)."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import types
import unittest
import contextlib
from pathlib import Path
from unittest.mock import patch

from binary_inspector import dotnet, settings, triage
from binary_inspector.__main__ import main
from binary_inspector.compare import compare_analyses, format_comparison
from binary_inspector.pe import Import, analyze_bytes, imphash, pe_checksum
from tests.test_pe import make_pe32, make_pe32plus, set_directory


class HashTests(unittest.TestCase):
    def test_imphash_follows_pefile(self):
        imports = (
            Import("kernel32.dll", ("ExitProcess", "GetProcAddress")),
            Import("ws2_32.dll", ("ordinal_115", "ordinal_9999")),
            Import("oleaut32.dll", ("ordinal_2",)),
            Import("custom.ocx", ("Init",)),
        )
        expected = ",".join([
            "kernel32.exitprocess", "kernel32.getprocaddress", "ws2_32.wsastartup", "ws2_32.ord9999",
            "oleaut32.sysallocstring", "custom.init",
        ])
        self.assertEqual(imphash(imports), hashlib.md5(expected.encode()).hexdigest())
        self.assertEqual(imphash(()), "")

    def test_the_checksum_matches_the_reference_algorithm(self):
        """pefile's generate_checksum(): 32-bit words with carries folded, then 16-bit, plus the length."""

        def reference(data: bytes, offset: int) -> int:
            padded = data + bytes((4 - len(data) % 4) % 4)
            checksum = 0
            for index in range(len(padded) // 4):
                if index == offset // 4:
                    continue
                checksum = (checksum & 0xFFFFFFFF) + struct.unpack_from("<I", padded, index * 4)[0] + (checksum >> 32)
                if checksum > 2 ** 32:
                    checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum = checksum + (checksum >> 16)
            return (checksum & 0xFFFF) + len(data)

        for data in (make_pe32(), make_pe32plus() + b"\x07\xff\x10", bytes(range(256)) * 50 + b"x"):
            self.assertEqual(pe_checksum(data, 0xD8), reference(data, 0xD8))

    def test_reports_carry_md5_sha1_section_hashes_and_both_checksums(self):
        report = analyze_bytes(make_pe32())
        data = make_pe32()
        self.assertEqual(report.md5, hashlib.md5(data).hexdigest())
        self.assertEqual(report.sha1, hashlib.sha1(data).hexdigest())
        self.assertEqual(report.sections[0].sha256, hashlib.sha256(data[0x200:0x600]).hexdigest())
        self.assertEqual(report.checksum_stored, 0)
        self.assertEqual(report.checksum_computed, pe_checksum(data, 0x98 + 64))


class StringTests(unittest.TestCase):
    def test_categories(self):
        cases = {
            "https://example.com/a": "url", "10.0.0.1": "ip", "4.0.0.0": "", 'version="5.1.0.0"': "",
            "me@example.org": "email", "HKEY_LOCAL_MACHINE\\Software": "registry", "C:\\Windows\\Temp": "path",
            "S:\\2": "", "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=": "base64", "CreateToolhelp32Snapshot": "",
            "Hello World": "",
        }
        for value, category in cases.items():
            self.assertEqual(triage.string_category(value), category, value)

    def test_notable_strings_are_kept_first(self):
        data = bytearray(make_pe32())
        data[0x2A0:0x2BA] = b"https://example.com/update"
        report = analyze_bytes(bytes(data))
        self.assertEqual((report.strings[0], report.string_categories[0]), ("https://example.com/update", "url"))
        self.assertEqual(len(report.strings), len(report.string_categories))
        self.assertIn("hello world", report.strings)


class HintTests(unittest.TestCase):
    def test_imports_are_grouped_by_behaviour(self):
        hints = triage.api_hints((
            Import("kernel32.dll", ("CreateRemoteThread", "WriteProcessMemory", "IsDebuggerPresent", "Sleep")),
            Import("user32.dll", ("SetWindowsHookExW",)),
        ))
        groups = {hint.behaviour: hint.functions for hint in hints}
        self.assertEqual(groups["process injection"], ("kernel32.dll!CreateRemoteThread", "kernel32.dll!WriteProcessMemory"))
        self.assertEqual(groups["keyboard and input capture"], ("user32.dll!SetWindowsHookExW",))
        self.assertIn("debugger detection", groups)
        self.assertEqual(len(groups), 3)

    def test_packers_and_toolchains(self):
        data = bytearray(make_pe32())
        data[0x178:0x180] = b"UPX0\0\0\0\0"
        names = [hint.name for hint in analyze_bytes(bytes(data)).toolchain_hints]
        self.assertIn("UPX packer", names)
        go = analyze_bytes(make_pe32() + b"\xff Go buildinf:" + bytes(16))
        self.assertIn("Go", [hint.name for hint in go.toolchain_hints])
        data = bytearray(make_pe32(False))
        key = 0x1234
        for index, word in enumerate([0x536E6144, 0, 0, 0, (258 << 16) | 33145, 3]):
            struct.pack_into("<I", data, 0x40 + index * 4, word ^ key)
        data[0x58:0x5C] = b"Rich"
        struct.pack_into("<I", data, 0x5C, key)
        msvc = [hint.name for hint in analyze_bytes(bytes(data)).toolchain_hints]
        self.assertIn("Microsoft linker (Visual Studio 2022 or later)", msvc)


def _metadata() -> tuple[bytes, bytes]:
    """A small .NET metadata blob: Module, ModuleRef, ImplMap, Assembly and AssemblyRef tables."""
    strings = b"\0test.dll\0Test\0mscorlib\0user32.dll\0MessageBoxW\0"
    offset = {name: strings.index(name.encode() + b"\0") for name in ("test.dll", "Test", "mscorlib", "user32.dll", "MessageBoxW")}
    guid = bytes(range(16))
    key = bytes(range(16))
    token = bytes.fromhex("b77a5c561934e089")
    blob = b"\0" + bytes([len(key)]) + key + bytes([len(token)]) + token
    tables = {
        0x00: [struct.pack("<HHHHH", 0, offset["test.dll"], 1, 0, 0)],
        0x1A: [struct.pack("<H", offset["user32.dll"])],
        0x1C: [struct.pack("<HHHH", 0, 0, offset["MessageBoxW"], 1)],
        0x20: [struct.pack("<IHHHHIHHH", 0x8004, 1, 2, 3, 4, 1, 1, offset["Test"], 0)],
        0x23: [struct.pack("<HHHHIHHHH", 4, 0, 0, 0, 0, 1 + 1 + len(key), offset["mscorlib"], 0, 0)],
    }
    valid = sum(1 << table for table in tables)
    stream = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    stream += b"".join(struct.pack("<I", len(rows)) for _, rows in sorted(tables.items()))
    stream += b"".join(b"".join(rows) for _, rows in sorted(tables.items()))
    stream += bytes((-len(stream)) % 4)
    streams = [("#~", stream), ("#Strings", strings + bytes((-len(strings)) % 4)), ("#GUID", guid),
               ("#Blob", blob + bytes((-len(blob)) % 4))]
    version = b"v4.0.30319\0\0"
    header = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(streams))
    names = [name.encode() + b"\0" + bytes((-(len(name) + 1)) % 4) for name, _ in streams]
    position = len(header) + sum(8 + len(name) for name in names)
    headers, bodies = b"", b""
    for (name, body), padded_name in zip(streams, names):
        headers += struct.pack("<II", position, len(body)) + padded_name
        bodies += body
        position += len(body)
    return header + headers + bodies, key


class DotNetTests(unittest.TestCase):
    def test_identity_references_and_pinvoke(self):
        metadata, key = _metadata()
        result = dotnet.read_metadata(metadata, 0x9, False)
        self.assertIsNone(result.error)
        self.assertEqual(result.runtime_version, "v4.0.30319")
        self.assertEqual(result.flags, ("IL_ONLY", "STRONG_NAME_SIGNED"))
        self.assertEqual((result.assembly_name, result.assembly_version), ("Test", "1.2.3.4"))
        self.assertEqual(result.public_key_token, hashlib.sha1(key).digest()[-8:][::-1].hex())
        self.assertEqual((result.module_name, result.mvid), ("test.dll", "03020100-0504-0706-0809-0a0b0c0d0e0f"))
        (reference,) = result.references
        self.assertEqual((reference.name, reference.version, reference.public_key_token),
                         ("mscorlib", "4.0.0.0", "b77a5c561934e089"))
        self.assertEqual(result.pinvoke_imports, ("user32.dll!MessageBoxW",))
        self.assertIn(("ImplMap", 1), result.table_rows)

    def test_damaged_metadata_is_an_error_on_this_part_only(self):
        self.assertIn("BSJB", dotnet.read_metadata(b"XXXX" + bytes(40), 1, False).error)
        metadata, _ = _metadata()
        truncated = dotnet.read_metadata(metadata[:120], 1, False)
        self.assertTrue(truncated.error)
        self.assertEqual(truncated.runtime_version, "v4.0.30319")

    @unittest.skipUnless(
        Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe").is_file(), "needs .NET Framework 4"
    )
    def test_a_real_assembly(self):
        from binary_inspector.pe import analyze_file

        metadata = analyze_file(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe").dotnet
        self.assertIsNone(metadata.error)
        self.assertEqual(metadata.assembly_name, "MSBuild")
        self.assertEqual(metadata.public_key_token, "b03f5f7f11d50a3a")
        self.assertIn("mscorlib", [reference.name for reference in metadata.references])


class CompareTests(unittest.TestCase):
    def test_differences_between_two_versions(self):
        old = analyze_bytes(make_pe32(), "old.exe")
        data = bytearray(make_pe32(False))
        struct.pack_into("<H", data, 0x98 + 70, 0x0140)  # ASLR + DEP added
        new = analyze_bytes(bytes(data), "new.exe")
        diff = compare_analyses(old, new)
        self.assertFalse(diff["identical"])
        self.assertEqual(diff["imports_removed"], ["kernel32.dll!ExitProcess"])
        self.assertEqual(diff["mitigations"]["aslr"], {"old": False, "new": True})
        self.assertIn(".rdata", diff["sections_changed"])
        self.assertIn("Imports removed (1):", format_comparison(diff))
        same = compare_analyses(old, old)
        self.assertTrue(same["identical"])
        self.assertIn("identical", format_comparison(same))


class BatchTests(unittest.TestCase):
    def test_a_folder_gives_a_report_each_and_a_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            folder, out = Path(directory, "in"), Path(directory, "out")
            (folder / "sub").mkdir(parents=True)
            (folder / "a.exe").write_bytes(make_pe32())
            (folder / "sub" / "b.dll").write_bytes(make_pe32plus())
            (folder / "broken.dll").write_bytes(b"not a PE")
            (folder / "notes.txt").write_text("ignored")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(folder), "--out", str(out), "--recursive"]), 0)
            self.assertEqual(sorted(path.name for path in out.iterdir()), ["a.exe.json", "sub__b.dll.json", "summary.csv"])
            rows = {row["file"]: row for row in csv.DictReader((out / "summary.csv").open(encoding="utf-8"))}
            self.assertEqual(set(rows), {"a.exe", "broken.dll", os.path.join("sub", "b.dll")})
            self.assertIn("DOS/PE header", rows["broken.dll"]["error"])
            self.assertEqual(json.loads((out / "a.exe.json").read_text())["file_name"], "a.exe")

    def test_a_folder_needs_out(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main([directory])


class _FakeYara(types.ModuleType):
    """Stands in for yara-python: one rule that matches when the data contains b"hello"."""

    class Error(Exception):
        pass

    class TimeoutError(Error):
        pass

    def compile(self, filepaths):
        self.compiled_with = filepaths
        fake = self

        class Rules:
            def match(self, data, timeout):
                fake.timeout = timeout
                if b"hello" not in data:
                    return []
                instance = types.SimpleNamespace(offset=data.index(b"hello"))
                string = types.SimpleNamespace(identifier="$h", instances=[instance])
                return [types.SimpleNamespace(rule="Hello", namespace="demo", tags=["t"],
                                              meta={"description": "says hello"}, strings=[string])]

        return Rules()


class YaraTests(unittest.TestCase):
    def test_a_scan_with_rules_from_a_folder(self):
        from binary_inspector import yara_scan

        fake = _FakeYara("yara")
        with tempfile.TemporaryDirectory() as directory, patch.dict(sys.modules, {"yara": fake}):
            Path(directory, "demo.yar").write_text("rule Hello { condition: true }")
            Path(directory, "nested").mkdir()
            Path(directory, "nested", "more.yara").write_text("rule X { condition: false }")
            matches = yara_scan.scan_bytes(make_pe32(), directory, timeout=5)
        self.assertEqual(sorted(fake.compiled_with), ["demo", "nested/more"])
        self.assertEqual(fake.timeout, 5)
        (match,) = matches
        self.assertEqual((match.rule, match.namespace, match.tags), ("Hello", "demo", ("t",)))
        self.assertEqual(match.strings, ("$h at 0x240",))
        text = yara_scan.format_matches(yara_scan.matches_to_dict(matches, directory))
        self.assertIn("demo:Hello [t]", text)

    def test_without_yara_python_the_error_says_how_to_install_it(self):
        from binary_inspector import yara_scan

        with patch.dict(sys.modules, {"yara": None}):
            with self.assertRaisesRegex(yara_scan.YaraError, "pip install yara-python"):
                yara_scan.scan_bytes(b"MZ", ".")


class SettingsTests(unittest.TestCase):
    def test_recent_files_and_a_damaged_settings_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"BINARY_INSPECTOR_SETTINGS_DIR": directory}):
            self.assertEqual(settings.load(), {"recent": [], "theme": "system"})
            recent = settings.with_recent(["C:\\a.exe", "C:\\b.exe"], "c:\\A.EXE")
            self.assertEqual(len(recent), 2)
            settings.save({"recent": recent, "theme": "dark"})
            self.assertEqual(settings.load()["theme"], "dark")
            Path(directory, "settings.json").write_text("{not json")
            self.assertEqual(settings.load()["theme"], "system")
            many = []
            for index in range(15):
                many = settings.with_recent(many, f"C:\\{index}.exe")
            self.assertEqual(len(many), settings.MAX_RECENT)


if __name__ == "__main__":
    unittest.main()
