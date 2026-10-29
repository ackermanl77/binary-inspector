from __future__ import annotations

import unittest
from unittest import mock

from binary_inspector.windows_dnd import WindowsFileDropTarget, _DROP_QUERY_COUNT, _WM_DROPFILES


class WindowsDropMessageTests(unittest.TestCase):
    def test_drop_paths_are_forwarded_and_native_handle_is_released(self):
        names = [r"C:\samples\app.exe", r"C:\samples\naïve.dll"]

        def query_file(_handle, index, buffer, _length):
            if index == _DROP_QUERY_COUNT:
                return len(names)
            if buffer is None:
                return len(names[index])
            buffer.value = names[index]
            return len(names[index])

        target = WindowsFileDropTarget.__new__(WindowsFileDropTarget)
        target._drag_query_file = mock.Mock(side_effect=query_file)
        target._drag_finish = mock.Mock()
        target._on_drop = mock.Mock()
        target._call_window_proc = mock.Mock()

        result = target._dispatch(10, _WM_DROPFILES, 25, 0)

        self.assertEqual(result, 0)
        target._on_drop.assert_called_once_with(tuple(names))
        target._drag_finish.assert_called_once_with(25)
        target._call_window_proc.assert_not_called()

    def test_other_window_messages_are_forwarded_to_tk(self):
        target = WindowsFileDropTarget.__new__(WindowsFileDropTarget)
        target._previous_window_proc = 99
        target._call_window_proc = mock.Mock(return_value=123)

        result = target._dispatch(10, 0x000F, 2, 3)

        self.assertEqual(result, 123)
        target._call_window_proc.assert_called_once_with(99, 10, 0x000F, 2, 3)

    def test_drop_handle_is_released_when_path_handling_fails(self):
        target = WindowsFileDropTarget.__new__(WindowsFileDropTarget)
        target._paths_from_drop = mock.Mock(side_effect=OSError("bad drop handle"))
        target._drag_finish = mock.Mock()

        with self.assertRaisesRegex(OSError, "bad drop handle"):
            target._dispatch(10, _WM_DROPFILES, 25, 0)

        target._drag_finish.assert_called_once_with(25)


if __name__ == "__main__":
    unittest.main()
