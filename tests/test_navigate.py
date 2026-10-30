"""Address conversion and the hex dump behind the GUI's Go to and Hex tab."""
from __future__ import annotations

import unittest

from binary_inspector import navigate
from binary_inspector.pe import analyze_bytes
from tests.test_pe import make_pe32

# make_pe32(): one section, .rdata, at RVA 0x1000, file offset 0x200, 0x400 bytes on disk,
# 0x300 virtual; image base 0x400000; the file is 0x600 bytes.


class ParseAddressTests(unittest.TestCase):
    def test_hex_forms_and_decimal(self):
        for text in ("1A2B", "0x1a2b", "1A2Bh", " 1a2b ", "1_A2B"):
            self.assertEqual(navigate.parse_address(text), 0x1A2B, text)
        self.assertEqual(navigate.parse_address("#100"), 100)

    def test_bad_input(self):
        for text in ("", "   ", "xyz"):
            with self.assertRaises(ValueError):
                navigate.parse_address(text)


class LocateTests(unittest.TestCase):
    def setUp(self):
        self.analysis = analyze_bytes(make_pe32(), "sample.exe")

    def test_rva_in_a_section(self):
        location = navigate.locate(self.analysis, 0x1010, "rva")
        self.assertEqual(location, navigate.Location(rva=0x1010, offset=0x210, section=".rdata"))

    def test_virtual_address_is_rva_plus_image_base(self):
        self.assertEqual(navigate.locate(self.analysis, 0x401010, "va").offset, 0x210)
        with self.assertRaises(ValueError):
            navigate.locate(self.analysis, 0x10, "va")

    def test_offset_back_to_rva(self):
        location = navigate.locate(self.analysis, 0x210, "offset")
        self.assertEqual((location.rva, location.section), (0x1010, ".rdata"))

    def test_headers_and_past_the_end(self):
        self.assertEqual(navigate.locate(self.analysis, 0x80, "offset").section, "")
        self.assertEqual(navigate.locate(self.analysis, 0x80, "rva").offset, 0x80)
        with self.assertRaises(ValueError):
            navigate.locate(self.analysis, 0x600, "offset")
        self.assertEqual(navigate.locate(self.analysis, 0x9000, "rva"),
                         navigate.Location(rva=0x9000, offset=None, section="(none)"))

    def test_describe(self):
        text = navigate.describe(navigate.locate(self.analysis, 0x1010, "rva"), self.analysis.image_base)
        self.assertEqual(text, "RVA 0x1010 (VA 0x401010), file offset 0x210, in .rdata")


class HexLinesTests(unittest.TestCase):
    def test_layout(self):
        (line,) = navigate.hex_lines(bytes(range(0x41, 0x51)), 0x200)
        self.assertEqual(line, "00000200  41 42 43 44 45 46 47 48  49 4A 4B 4C 4D 4E 4F 50  ABCDEFGHIJKLMNOP")
        (short,) = navigate.hex_lines(b"\x00A", 0)
        self.assertTrue(short.startswith("00000000  00 41 "))
        self.assertTrue(short.endswith("  .A"))

    def test_pages(self):
        self.assertEqual(navigate.page_start(0x1234), 0x1000)
        self.assertEqual(len(navigate.hex_lines(bytes(40), 0)), 3)


if __name__ == "__main__":
    unittest.main()
