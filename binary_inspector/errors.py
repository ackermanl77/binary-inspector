"""Uncaught errors in the desktop app, written to error.log next to settings.json: the packaged
exe is windowed, so a traceback has no console to appear in. The log is capped at about 1 MB
(the previous one is kept as error.log.1)."""

from __future__ import annotations

import datetime
import traceback
from pathlib import Path

from . import settings

MAX_LOG_BYTES = 1_000_000


def log_path() -> Path:
    return settings.settings_path().with_name("error.log")


def record(exc_type, exc, tb) -> Path | None:
    """Append the traceback to the error log; the log's path, or None if it can't be written."""
    path = log_path()
    text = "".join(traceback.format_exception(exc_type, exc, tb))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            path.replace(path.with_name("error.log.1"))
        with path.open("a", encoding="utf-8") as log:
            log.write(f"--- {datetime.datetime.now().isoformat(timespec='seconds')}\n{text}\n")
    except OSError:
        return None
    return path
