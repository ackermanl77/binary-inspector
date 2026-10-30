from __future__ import annotations

import os
import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from binary_inspector.signature import _FileTime, _filetime_utc, _status_for_result, verify_authenticode
from binary_inspector.__main__ import main
from tests.test_pe import make_pe32


class SignatureTests(unittest.TestCase):
    def test_classifies_trusted_unsigned_untrusted_and_unknown_results(self):
        self.assertEqual(_status_for_result(0).status, "trusted")
        self.assertEqual(_status_for_result(0x800B0100).status, "unsigned")
        self.assertEqual(_status_for_result(0x80096010).status, "untrusted")
        self.assertEqual(_status_for_result(0x800B0102).status, "unable_to_verify")
        self.assertEqual(_status_for_result(-2146762496).status, "unsigned")

    def test_non_windows_reports_unavailable_without_loading_windows_apis(self):
        with patch("binary_inspector.signature.os.name", "posix"):
            result = verify_authenticode("not-used.exe")
        self.assertEqual(result.status, "unable_to_verify")
        self.assertIsNone(result.status_code)
        self.assertIn("only available on Windows", result.detail)

    def test_cli_includes_signature_verification_in_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "sample.exe")
            path.write_bytes(make_pe32())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main([str(path), "--verify-signature"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertIn("authenticode_verification", report["extended_analysis"])
        self.assertEqual(
            report["extended_analysis"]["authenticode_verification"]["status"],
            "unsigned" if os.name == "nt" else "unable_to_verify",
        )

    @unittest.skipUnless(os.name == "nt", "Windows trust API integration test")
    def test_unsigned_file_is_reported_as_unsigned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "unsigned.bin")
            path.write_bytes(make_pe32())
            result = verify_authenticode(path)
        self.assertEqual(result.status, "unsigned")
        self.assertIsNone(result.source)

    def test_trusted_results_carry_where_the_signature_came_from(self):
        result = _status_for_result(0, "catalog", "Microsoft Windows", "Microsoft Windows PCA", "x.cat")
        self.assertEqual((result.status, result.source, result.catalog), ("trusted", "catalog", "x.cat"))
        self.assertIn("catalog signature", result.detail)
        self.assertEqual(result.to_dict()["signer"], "Microsoft Windows")
        self.assertIsNone(_status_for_result(0x800B0100, "embedded").source)  # unsigned: no source

    def test_windows_filetime_is_reported_as_signature_metadata_not_current_trust(self):
        instant = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        ticks = int((instant - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
        filetime = _FileTime(ticks & 0xFFFFFFFF, ticks >> 32)
        timestamp = _filetime_utc(filetime)
        self.assertEqual(timestamp, "2024-01-02T03:04:05+00:00")

        result = _status_for_result(0, "embedded", signing_time_utc=timestamp)
        self.assertEqual(result.to_dict()["signing_time_utc"], timestamp)
        self.assertIn("not current certificate trust", result.detail)


_SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


@unittest.skipUnless(os.name == "nt", "Windows trust API integration tests")
class WindowsSystemFileTests(unittest.TestCase):
    """Real system files: Notepad is catalog-signed (no embedded signature), kernel32 is embedded."""

    def test_a_catalog_signed_system_file_is_trusted_through_its_catalog(self):
        notepad = _SYSTEM32 / "notepad.exe"
        if not notepad.is_file():
            self.skipTest("notepad.exe is not installed")
        result = verify_authenticode(notepad)
        if result.source == "embedded":
            self.skipTest("this Windows build signs notepad.exe in the file")
        self.assertEqual((result.status, result.source), ("trusted", "catalog"))
        self.assertIn("Microsoft", result.signer)
        self.assertTrue(result.catalog.lower().endswith(".cat"))

    def test_a_changed_copy_is_no_longer_listed_by_the_catalog(self):
        notepad = _SYSTEM32 / "notepad.exe"
        if not notepad.is_file() or verify_authenticode(notepad).source != "catalog":
            self.skipTest("needs a catalog-signed notepad.exe")
        data = bytearray(notepad.read_bytes())
        data[0x40] ^= 0xFF  # inside the DOS stub: still a valid PE, but a different hash
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory, "notepad.exe")
            copy.write_bytes(bytes(data))
            result = verify_authenticode(copy)
        self.assertEqual(result.status, "unsigned")

    def test_an_embedded_signature_reports_its_signer(self):
        result = verify_authenticode(_SYSTEM32 / "kernel32.dll")
        self.assertEqual((result.status, result.source), ("trusted", "embedded"))
        self.assertIn("Microsoft", result.signer)
        self.assertTrue(result.issuer)


if __name__ == "__main__":
    unittest.main()
