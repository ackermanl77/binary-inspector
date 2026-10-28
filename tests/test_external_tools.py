from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from binary_inspector import external_tools
from binary_inspector.external_tools import ToolError, _run_bounded


class ExternalToolTests(unittest.TestCase):
    def test_runs_fixed_argument_list_without_a_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory, "sample with spaces.exe")
            sample.write_bytes(b"sample")
            result = _run_bounded(
                sys.executable,
                ["-c", "import sys; print(sys.argv[-1])"],
                sample,
            )
        self.assertIn("sample with spaces.exe", result.output)
        self.assertFalse(result.truncated)

    def test_bounds_and_marks_tool_output(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory, "sample.exe")
            sample.write_bytes(b"sample")
            with patch.object(external_tools, "MAX_TOOL_OUTPUT_BYTES", 32):
                result = _run_bounded(
                    sys.executable,
                    ["-c", "print('x' * 200)"],
                    sample,
                )
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.output.encode("utf-8")), 32)

    def test_rejects_missing_tool_and_invalid_timeout(self):
        with patch.dict(os.environ, {"BINARY_INSPECTOR_RIZIN": ""}), patch(
            "binary_inspector.external_tools.shutil.which", return_value=None
        ):
            with self.assertRaisesRegex(ToolError, "not found"):
                external_tools.disassemble_native("unused.exe")
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory, "sample.exe")
            sample.write_bytes(b"sample")
            with self.assertRaises(ValueError):
                _run_bounded(sys.executable, [], sample, timeout_seconds=0)

    def test_terminates_tool_at_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory, "sample.exe")
            sample.write_bytes(b"sample")
            started = time.monotonic()
            with self.assertRaisesRegex(ToolError, "time limit"):
                _run_bounded(
                    sys.executable,
                    ["-c", "import time; time.sleep(10)"],
                    sample,
                    timeout_seconds=1,
                )
            self.assertLess(time.monotonic() - started, 5)

    def test_terminates_tool_when_it_exceeds_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory, "sample.exe")
            sample.write_bytes(b"sample")
            with patch.object(external_tools, "MAX_TOOL_OUTPUT_BYTES", 32):
                started = time.monotonic()
                with self.assertRaisesRegex(ToolError, "output exceeded"):
                    _run_bounded(
                        sys.executable,
                        ["-c", "import time; print('x' * 10000, flush=True); time.sleep(10)"],
                        sample,
                        timeout_seconds=5,
                    )
            self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
