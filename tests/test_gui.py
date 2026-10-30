"""The tabbed window (UI1): the tables it fills, sorting, the strings filter, copying rows and the
Summary notes. Needs a Tk display; skipped where there is none."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from binary_inspector import errors, findings, update_check
from binary_inspector.gui import InspectorWindow, sort_key
from binary_inspector.pe import analyze_bytes
from tests.test_pe import make_pe32, make_resource_pe

# The window saves its theme and recent files; keep that out of the real %APPDATA%.
_SETTINGS = tempfile.TemporaryDirectory()
os.environ["BINARY_INSPECTOR_SETTINGS_DIR"] = _SETTINGS.name


def tearDownModule():
    _SETTINGS.cleanup()

try:
    import tkinter as tk

    _ROOT = tk.Tk()
    _ROOT.withdraw()
except Exception:  # noqa: BLE001 - no display (CI without a desktop)
    _ROOT = None


def _values(tree) -> list[tuple]:
    return [tuple(tree.item(item, "values")) for item in tree.get_children("")]


class SortKeyTests(unittest.TestCase):
    def test_numbers_hex_and_text(self):
        values = ["0x1A", "text", "9", "1,200", "0x2", "Alpha"]
        self.assertEqual(sorted(values, key=sort_key), ["0x2", "9", "0x1A", "1,200", "Alpha", "text"])


class DroppedFileTests(unittest.TestCase):
    def test_one_dropped_path_uses_the_regular_open_flow(self):
        window = SimpleNamespace(open_file=mock.Mock(), status=mock.Mock())
        InspectorWindow._open_dropped_files(window, (r"C:\samples\app.exe",))
        window.open_file.assert_called_once_with(r"C:\samples\app.exe")
        window.status.set.assert_not_called()

    def test_multiple_dropped_paths_are_rejected_with_guidance(self):
        window = SimpleNamespace(open_file=mock.Mock(), status=mock.Mock())
        InspectorWindow._open_dropped_files(window, (r"C:\samples\a.exe", r"C:\samples\b.dll"))
        window.open_file.assert_not_called()
        window.status.set.assert_called_once_with("Drop one executable at a time.")


class FindingTests(unittest.TestCase):
    def test_an_unhardened_import_less_file(self):
        notes = findings.summary_findings(analyze_bytes(make_pe32(False)))
        texts = " ".join(note.text for note in notes)
        self.assertIn("Signature not checked", texts)
        self.assertIn("No imported functions", texts)
        self.assertIn("No ASLR", texts)
        self.assertIn("No DEP", texts)
        self.assertTrue(all(note.level in (findings.WARN, findings.INFO, findings.OK) for note in notes))

    def test_signature_results_and_hardening(self):
        data = bytearray(make_pe32())
        struct.pack_into("<H", data, 0x98 + 70, 0x0040 | 0x0100)  # ASLR + DEP, no CFG
        verification = {"status": "trusted", "source": "catalog", "signer": "Microsoft Windows"}
        notes = findings.summary_findings(
            analyze_bytes(bytes(data)), {"authenticode-verification": {"verification": verification}}
        )
        self.assertIn(findings.Finding(findings.OK, "Signed by Microsoft Windows through a system catalog."), notes)
        self.assertIn(findings.Finding(findings.INFO, "Built without Control Flow Guard."), notes)
        self.assertFalse(any("No ASLR" in note.text for note in notes))

    def test_an_appended_container_is_mentioned(self):
        notes = findings.summary_findings(analyze_bytes(make_pe32() + b"PK\x03\x04" + bytes(60)))
        self.assertTrue(any("ZIP archive" in note.text for note in notes))


@unittest.skipIf(_ROOT is None, "no Tk display")
class WindowTests(unittest.TestCase):
    def setUp(self):
        self.top = tk.Toplevel(_ROOT)
        self.window = InspectorWindow(self.top)

    def tearDown(self):
        self.top.destroy()

    def _show(self, data: bytes) -> None:
        self.window._results.put((Path("sample.exe"), analyze_bytes(data, "sample.exe"), None, None))
        self.window._poll_results()

    def test_every_tab_is_filled_from_one_analysis(self):
        self._show(make_resource_pe())
        window = self.window
        tabs = [window.notebook.tab(tab, "text") for tab in window.notebook.tabs()]
        self.assertEqual(
            tabs,
            ["Summary", "Sections", "Imports", "Exports", "Resources", "Security", ".NET", "Strings", "Hex", "Tools",
             "Full report"],
        )
        facts = dict(_values(window.facts_table))
        self.assertEqual(facts["File"], "sample.exe")
        self.assertEqual(facts["FileVersion"], "1.2.34")
        self.assertEqual(_values(window.sections_table)[0][:3], (".rdata", "0x00001000", "0x00000200"))
        version = window.resources_table.get_children("")[0]
        self.assertEqual(window.resources_table.item(version, "text"), "RT_VERSION (16)")
        fields = [window.resources_table.item(child, "text") for child in window.resources_table.get_children(version)]
        self.assertEqual(fields, ["FileVersion", "ProductName", "OriginalFilename"])
        security = dict(_values(window.security_table))
        self.assertEqual(security["Subsystem"], "Unknown (0)")
        self.assertIn("DEP / NX", security)
        self.assertIn("BINARY INSPECTOR - STATIC REPORT", window.output.get("1.0", "end"))
        self.assertTrue(window.findings_table.get_children(""))

    def test_imports_are_a_tree_of_libraries_and_functions(self):
        self._show(make_pe32())
        tree = self.window.imports_table
        (library,) = tree.get_children("")
        self.assertEqual(tree.item(library, "text"), "kernel32.dll")
        self.assertEqual(tree.set(library), {"Kind": "import", "Functions": "1"})
        tree.selection_set(library)
        self.window._copy_rows(tree)
        self.assertEqual(self.top.clipboard_get(), "kernel32.dll\timport\t1")  # the tree column too
        self.assertEqual([tree.item(child, "text") for child in tree.get_children(library)], ["ExitProcess"])

    def test_header_clicks_sort_by_value_and_reverse(self):
        self._show(make_resource_pe())
        table = self.window.facts_table
        self.window._sort(table, "Property")
        names = [row[0] for row in _values(table)]
        self.assertEqual(names, sorted(names, key=str.lower))
        self.window._sort(table, "Property")
        self.assertEqual([row[0] for row in _values(table)], sorted(names, key=str.lower, reverse=True))

    def test_the_strings_filter_and_copying_rows(self):
        self._show(make_pe32())
        window = self.window
        everything = len(window.strings_table.get_children(""))
        window.strings_filter.set("hello")
        self.assertEqual([row[1] for row in _values(window.strings_table)], ["hello world"])
        self.assertIn("1 shown of", window.strings_count.get())
        window.strings_filter.set("")
        self.assertEqual(len(window.strings_table.get_children("")), everything)
        rows = window.sections_table.get_children("")
        window.sections_table.selection_set(rows)
        window._copy_rows(window.sections_table)
        self.assertTrue(self.top.clipboard_get().startswith(".rdata\t0x00001000"))

    def test_a_failed_analysis_clears_the_tables_and_says_why(self):
        self._show(make_pe32())
        self.window._analysis = None  # as open_file() does before reading the next file
        self.window._results.put((Path("broken.exe"), None, "The PE signature is missing.", None))
        self.window._poll_results()
        self.assertEqual(self.window.sections_table.get_children(""), ())
        (note,) = _values(self.window.findings_table)
        self.assertIn("The PE signature is missing.", note[1])

    def test_tool_results_appear_in_the_tools_tab(self):
        self._show(make_pe32())
        verification = {"status": "unsigned", "status_code": 0x800B0100, "detail": "No signature.", "source": None}
        self.window._results.put(
            (Path("sample.exe"), None, None,
             {"authenticode-verification": {"kind": "signature-verification", "verification": verification}})
        )
        self.window._poll_results()
        self.assertIn("AUTHENTICODE TRUST VERIFICATION", self.window.tools_output.get("1.0", "end"))
        self.assertTrue(any("Not signed" in row[1] for row in _values(self.window.findings_table)))
        self.assertEqual(dict(_values(self.window.facts_table))["Signature"], "unsigned")

    def test_every_table_filter_hides_rows_and_survives_a_refill(self):
        self._show(make_pe32())
        window, tree = self.window, self.window.imports_table
        window._filters[str(tree)].set("exitprocess")  # matches a child row: its library stays
        self.assertEqual(len(tree.get_children("")), 1)
        window._filters[str(tree)].set("nothing-like-this")
        self.assertEqual(tree.get_children(""), ())
        self._show(make_pe32())  # refilled with the filter still typed
        self.assertEqual(tree.get_children(""), ())
        window._filters[str(tree)].set("")
        self.assertEqual(len(tree.get_children("")), 1)
        for table in (window.sections_table, window.exports_table, window.resources_table, window.security_table):
            self.assertIn(str(table), window._filters)

    def test_ctrl_number_selects_a_tab(self):
        self.window._select_tab(8)
        self.assertEqual(self.window.notebook.tab(self.window.notebook.select(), "text"), "Hex")
        self.window._select_tab(40)  # no such tab: nothing changes
        self.assertEqual(self.window.notebook.tab(self.window.notebook.select(), "text"), "Hex")

    def test_the_command_list_offers_menus_enabled_tools_and_tabs(self):
        labels = [label for label, _action in self.window.commands()]
        self.assertIn("Open executable", labels)
        self.assertIn("Theme: dark", labels)
        self.assertIn("Tab: Hex", labels)
        self.assertNotIn("YARA scan", labels)  # disabled until a file is open
        self._show(make_pe32())
        self.assertIn("YARA scan", [label for label, _action in self.window.commands()])
        dict(self.window.commands())["Tab: Strings"]()
        self.assertEqual(self.window.notebook.tab(self.window.notebook.select(), "text"), "Strings")

    def test_the_hex_tab_reads_the_file_a_page_at_a_time(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "sample.exe")
            path.write_bytes(make_pe32())
            self.window._input_path = path
            self._show(path.read_bytes())
            self.window.show_hex(0x210, mark=0x210)
            dump = self.window.hex_output.get("1.0", "end")
            self.assertTrue(dump.startswith("00000000  4D 5A"))  # "MZ", page from offset 0
            self.assertIn("0x0-0x5FF of 0x600 bytes (headers, .rdata)", self.window.hex_where.get())
            self.assertEqual(self.window.hex_output.tag_names("33.0"), ("section0",))  # 0x200: .rdata starts
            self.assertEqual(self.window.hex_output.tag_names("32.0"), ())  # headers: no section colour
            self.assertEqual(self.window.hex_output.tag_ranges("mark")[0].string, "34.0")  # 0x210 // 16 + 1

    def test_the_start_screen_lists_recent_files_until_one_is_open(self):
        window = self.window
        window._settings["recent"] = [r"C:\samples\a.exe"]
        window._show_start()
        rows = _values(window.facts_table)
        self.assertEqual(rows[0][0], "Open a file")
        self.assertEqual(rows[1], ("Recent (double-click)", r"C:\samples\a.exe"))
        self._show(make_pe32())
        self.assertNotIn("Open a file", dict(_values(window.facts_table)))


@unittest.skipIf(_ROOT is None, "no Tk display")
class NewToolsWindowTests(unittest.TestCase):
    def setUp(self):
        self.top = tk.Toplevel(_ROOT)
        self.window = InspectorWindow(self.top)

    def tearDown(self):
        self.top.destroy()

    def _show(self, data: bytes) -> None:
        self.window._results.put((Path("sample.exe"), analyze_bytes(data, "sample.exe"), None, None))
        self.window._poll_results()

    def test_strings_can_be_narrowed_to_a_kind(self):
        data = bytearray(make_pe32())
        data[0x2A0:0x2BA] = b"https://example.com/update"
        self._show(bytes(data))
        window = self.window
        window.strings_kind.set("url")
        window._fill_strings()
        self.assertEqual(_values(window.strings_table), [("url", "https://example.com/update")])
        window.strings_kind.set("notable")
        window._fill_strings()
        self.assertEqual(len(window.strings_table.get_children("")), 1)

    def test_summary_shows_the_hashes_and_checksum(self):
        self._show(make_pe32())
        facts = dict(_values(self.window.facts_table))
        self.assertEqual(len(facts["MD5"]), 32)
        self.assertEqual(len(facts["Imphash"]), 32)
        self.assertTrue(facts["Checksum"].startswith("not set"))

    def test_the_dotnet_tab_says_when_a_file_is_native(self):
        self._show(make_pe32())
        (row,) = self.window.dotnet_table.get_children("")
        self.assertEqual(self.window.dotnet_table.item(row, "text"), "Not a .NET assembly")

    def test_opening_a_file_puts_it_first_in_open_recent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "app.exe")
            path.write_bytes(make_pe32())
            self.window.open_file(str(path))
            self.assertEqual(self.window._settings["recent"][0], str(path))
            self.assertEqual(self.window.recent_menu.entrycget(0, "label"), str(path))
            for _ in range(100):  # let the worker thread finish before the folder goes
                self.top.update()
                if self.window._analysis is not None:
                    break
                self.top.after(20)

    def test_the_dark_theme_recolours_the_text_views(self):
        self.window.apply_theme("dark")
        self.assertEqual(self.window._style.theme_use(), "clam")
        self.assertEqual(str(self.window.output.cget("background")), InspectorWindow._PALETTES["dark"]["field"])
        self.window.apply_theme("light")
        self.assertEqual(str(self.window.output.cget("background")), InspectorWindow._PALETTES["light"]["field"])

    def test_comparison_and_yara_results_appear_in_the_tools_tab(self):
        from binary_inspector.compare import compare_analyses

        self._show(make_pe32())
        old = analyze_bytes(make_pe32(), "old.exe")
        new = analyze_bytes(make_pe32(False), "new.exe")
        yara = {"rules": "rules.yar", "match_count": 1, "matches": [
            {"rule": "Demo", "namespace": "rules", "tags": ["t"], "meta": {}, "strings": ["$a at 0x10"]}]}
        self.window._results.put((Path("sample.exe"), None, None, {
            "comparison": {"kind": "comparison", "diff": compare_analyses(old, new)},
            "yara": {"kind": "yara", "result": yara},
        }))
        self.window._poll_results()
        text = self.window.tools_output.get("1.0", "end")
        self.assertIn("COMPARISON: old.exe -> new.exe", text)
        self.assertIn("kernel32.dll!ExitProcess", text)
        self.assertIn("rules:Demo [t]", text)


@unittest.skipIf(_ROOT is None, "no Tk display")
class ErrorAndUpdateTests(unittest.TestCase):
    def setUp(self):
        self.top = tk.Toplevel(_ROOT)
        self.window = InspectorWindow(self.top)

    def tearDown(self):
        self.top.destroy()

    def test_an_uncaught_callback_error_is_logged_and_shown(self):
        try:
            raise RuntimeError("boom")
        except RuntimeError as exc:
            error = (type(exc), exc, exc.__traceback__)
        with mock.patch("binary_inspector.gui.messagebox.showerror") as showerror:
            self.top.report_callback_exception(*error)
        log = errors.log_path().read_text(encoding="utf-8")
        self.assertIn("RuntimeError: boom", log)
        self.assertIn(str(errors.log_path()), showerror.call_args[0][1])

    def test_an_update_offers_the_download_page(self):
        info = update_check.UpdateInfo("9.0.0", "https://example.com/get", "Faster")
        with mock.patch("binary_inspector.gui.messagebox.askyesno", return_value=True) as ask, \
                mock.patch("binary_inspector.gui.webbrowser.open") as open_page:
            self.window.show_update(info)
        self.assertIn("9.0.0", ask.call_args[0][1])
        open_page.assert_called_once_with("https://example.com/get")
        with mock.patch("binary_inspector.gui.messagebox.askyesno", return_value=False), \
                mock.patch("binary_inspector.gui.webbrowser.open") as open_page:
            self.window.show_update(info)
        open_page.assert_not_called()


if __name__ == "__main__":
    unittest.main()
