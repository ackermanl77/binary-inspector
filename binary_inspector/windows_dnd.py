"""Windows file-drop support for the Tk desktop window, without a Tcl DnD dependency."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Callable

_GWL_WNDPROC = -4
_WM_DROPFILES = 0x0233
_DROP_QUERY_COUNT = 0xFFFFFFFF


class WindowsFileDropTarget:
    """Subclass a Tk window procedure to receive shell WM_DROPFILES messages."""

    def __init__(self, hwnd: int, on_drop: Callable[[tuple[str, ...]], None]):
        if sys.platform != "win32":
            raise OSError("Windows file drop is only available on Windows")

        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        self._hwnd = hwnd
        self._on_drop = on_drop
        self._closed = False

        set_window_proc_name = (
            "SetWindowLongPtrW" if ctypes.sizeof(ctypes.c_void_p) == 8 else "SetWindowLongW"
        )
        self._set_window_proc = getattr(self._user32, set_window_proc_name)
        self._set_window_proc.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
        self._set_window_proc.restype = ctypes.c_ssize_t

        self._call_window_proc = self._user32.CallWindowProcW
        self._call_window_proc.argtypes = [
            ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        ]
        self._call_window_proc.restype = ctypes.c_ssize_t

        self._drag_query_file = self._shell32.DragQueryFileW
        self._drag_query_file.argtypes = [
            ctypes.c_void_p, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT,
        ]
        self._drag_query_file.restype = wintypes.UINT
        self._drag_finish = self._shell32.DragFinish
        self._drag_finish.argtypes = [ctypes.c_void_p]
        self._drag_finish.restype = None
        self._drag_accept_files = self._shell32.DragAcceptFiles
        self._drag_accept_files.argtypes = [wintypes.HWND, wintypes.BOOL]
        self._drag_accept_files.restype = None

        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
        )
        self._window_proc = callback_type(self._dispatch)
        ctypes.set_last_error(0)
        previous = self._set_window_proc(
            hwnd, _GWL_WNDPROC, ctypes.cast(self._window_proc, ctypes.c_void_p).value
        )
        if not previous and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        self._previous_window_proc = previous
        self._drag_accept_files(hwnd, True)

    def _dispatch(self, hwnd: int, message: int, wparam: int, lparam: int) -> int:
        if message != _WM_DROPFILES:
            return self._call_window_proc(self._previous_window_proc, hwnd, message, wparam, lparam)
        try:
            paths = self._paths_from_drop(wparam)
        finally:
            self._drag_finish(wparam)
        if paths:
            self._on_drop(tuple(paths))
        return 0

    def _paths_from_drop(self, drop_handle: int) -> list[str]:
        count = self._drag_query_file(drop_handle, _DROP_QUERY_COUNT, None, 0)
        paths = []
        for index in range(count):
            length = self._drag_query_file(drop_handle, index, None, 0)
            buffer = ctypes.create_unicode_buffer(length + 1)
            if self._drag_query_file(drop_handle, index, buffer, len(buffer)):
                paths.append(buffer.value)
        return paths

    def close(self) -> None:
        if self._closed:
            return
        self._drag_accept_files(self._hwnd, False)
        ctypes.set_last_error(0)
        previous = self._set_window_proc(self._hwnd, _GWL_WNDPROC, self._previous_window_proc)
        if not previous and ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
        self._closed = True
