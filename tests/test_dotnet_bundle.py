from __future__ import annotations

import struct
import unittest

from binary_inspector import dotnet
from binary_inspector.pe import analyze_bytes
from tests.test_pe import make_pe32


_MARKER = struct.pack("<I", 0x8B12B031)


def _bundle_fixture(major: int = 6, count: int = 3) -> bytes:
    data = bytearray(make_pe32(False))
    marker_offset = len(data) + 8
    header_offset = marker_offset + len(_MARKER)
    data.extend(struct.pack("<q", header_offset))
    data.extend(_MARKER)
    data.extend(struct.pack("<IIi", major, 0, count))
    bundle_id = b"fixture-id12"
    data.append(len(bundle_id))
    data.extend(bundle_id)
    if major >= 2:
        data.extend(struct.pack("<qqqqQ", 0, 0, 0, 0, 0))
    return bytes(data)


class DotNetBundleTests(unittest.TestCase):
    def test_detects_generated_bundle_header_and_reports_it_in_analysis(self):
        data = _bundle_fixture()
        bundle = dotnet.detect_bundle(data)
        self.assertEqual((bundle.version, bundle.embedded_file_count), ("6.0", 3))
        report = analyze_bytes(data)
        self.assertEqual(report.dotnet_bundle, bundle)
        self.assertIn("Single-file bundle: version 6.0", report.to_json())

    def test_detects_legacy_header_version(self):
        bundle = dotnet.detect_bundle(_bundle_fixture(1))
        self.assertEqual((bundle.version, bundle.embedded_file_count), ("1.0", 3))

    def test_excludes_a_trailing_authenticode_certificate_from_the_scan(self):
        data = _bundle_fixture() + b"certificate"
        bundle = dotnet.detect_bundle(data, len(_bundle_fixture()), len(b"certificate"))
        self.assertEqual((bundle.version, bundle.embedded_file_count), ("6.0", 3))

    def test_rejects_bad_offsets_versions_counts_and_truncated_headers(self):
        fixture = bytearray(_bundle_fixture())
        marker_offset = fixture.find(_MARKER)
        struct.pack_into("<q", fixture, marker_offset - 8, len(fixture) + 1)
        self.assertIsNone(dotnet.detect_bundle(bytes(fixture)))

        for major, count in ((5, 3), (6, -1), (6, dotnet.MAX_BUNDLE_FILES + 1)):
            self.assertIsNone(dotnet.detect_bundle(_bundle_fixture(major, count)))

        truncated = _bundle_fixture()[:-20]
        self.assertIsNone(dotnet.detect_bundle(truncated))

    def test_marker_without_a_valid_header_is_not_a_bundle(self):
        data = make_pe32(False) + bytes(8) + _MARKER + bytes(40)
        self.assertIsNone(dotnet.detect_bundle(data))


if __name__ == "__main__":
    unittest.main()
