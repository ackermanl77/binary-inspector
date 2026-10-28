from __future__ import annotations

import os
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from binary_inspector.signature import _status_for_result, verify_authenticode
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


if __name__ == "__main__":
    unittest.main()
