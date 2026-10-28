"""The desktop app's own settings: recently opened files and the colour theme, in a small JSON
file under %APPDATA%\\BinaryInspector (or BINARY_INSPECTOR_SETTINGS_DIR). A missing or damaged
file just means defaults; nothing about analysed files is stored except their paths."""

from __future__ import annotations

import json
import os
from pathlib import Path

MAX_RECENT = 10
THEMES = ("system", "light", "dark")


def settings_path() -> Path:
    override = os.environ.get("BINARY_INSPECTOR_SETTINGS_DIR")
    if override:
        return Path(override) / "settings.json"
    base = os.environ.get("APPDATA") or str(Path.home() / ".config")
    return Path(base) / "BinaryInspector" / "settings.json"


def load() -> dict:
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    recent = [str(item) for item in data.get("recent", []) if isinstance(item, str)][:MAX_RECENT]
    theme = data.get("theme") if data.get("theme") in THEMES else "system"
    return {"recent": recent, "theme": theme}


def save(data: dict) -> None:
    path = settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temporary.replace(path)
    except OSError:
        pass  # settings are a convenience; failing to save them must not stop the app


def with_recent(recent: list[str], path: str) -> list[str]:
    """`path` moved to the front (case-insensitively unique, as Windows paths are), trimmed."""
    key = os.path.normcase(os.path.abspath(path))
    kept = [item for item in recent if os.path.normcase(os.path.abspath(item)) != key]
    return [str(Path(path))] + kept[: MAX_RECENT - 1]


def windows_prefers_dark() -> bool:
    """Whether Windows is set to dark mode for apps (Settings > Personalization > Colors)."""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        ) as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
    except (ImportError, OSError):
        return False
