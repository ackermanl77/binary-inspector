"""Hints for triage: what the imported functions suggest a program can do (F1), which packer,
installer or toolchain produced it (B7), and which strings look like URLs, addresses, paths,
registry keys or encoded data (F5).

All of these are pattern matches on metadata already in the report. Plenty of legitimate programs
import "injection" or "network" functions; a hint says what to look at, never what a file is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---- imported functions grouped by behaviour (F1) --------------------------------------------

API_GROUPS: dict[str, tuple[str, ...]] = {
    "process injection": (
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtWriteVirtualMemory", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "NtQueueApcThread", "SetThreadContext", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "NtMapViewOfSection",
    ),
    "keyboard and input capture": (
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "RegisterRawInputDevices", "GetRawInputData", "AttachThreadInput",
    ),
    "network": (
        "WSAStartup", "connect", "send", "recv", "sendto", "recvfrom", "gethostbyname", "getaddrinfo",
        "InternetOpen", "InternetOpenUrl", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "InternetReadFile", "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "WinHttpReadData",
    ),
    "cryptography": (
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey", "CryptImportKey",
        "CryptDeriveKey", "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
        "BCryptOpenAlgorithmProvider", "CryptProtectData", "CryptUnprotectData",
    ),
    "debugger detection": (
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "NtSetInformationThread",
    ),
    "services and persistence": (
        "CreateService", "ChangeServiceConfig", "ChangeServiceConfig2", "StartService",
        "RegSetValueEx", "RegCreateKeyEx", "SHSetValue",
    ),
    "starting programs": ("CreateProcess", "CreateProcessAsUser", "ShellExecute", "ShellExecuteEx", "WinExec"),
    "privileges": ("AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken", "ImpersonateLoggedOnUser"),
    "loading code at run time": ("LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"),
}


def _base_name(function: str) -> str:
    """CreateProcessW -> CreateProcess (the ANSI/Unicode variants are one function)."""
    if len(function) > 2 and function[-1] in "AW" and function[-2].islower():
        return function[:-1]
    return function


_API_INDEX = {name.lower(): group for group, names in API_GROUPS.items() for name in names}


@dataclass(frozen=True)
class ApiHint:
    behaviour: str
    functions: tuple[str, ...]  # library!function, as imported


def api_hints(imports) -> tuple[ApiHint, ...]:
    """Imported functions grouped by what they are commonly used for, in API_GROUPS order."""
    found: dict[str, list[str]] = {}
    for library in imports:
        for function in library.functions:
            group = _API_INDEX.get(_base_name(function).lower())
            if group:
                found.setdefault(group, []).append(f"{library.library}!{function}")
    return tuple(ApiHint(group, tuple(found[group])) for group in API_GROUPS if group in found)


# ---- packer, installer and toolchain hints (B7) -----------------------------------------------

@dataclass(frozen=True)
class ToolchainHint:
    name: str
    evidence: str


# Visual Studio releases by the linker's build number (the Rich header's highest build).
_MSVC_BUILDS = (
    (30133, "Visual Studio 2022 or later"),
    (27508, "Visual Studio 2019"),
    (25017, "Visual Studio 2017"),
    (23026, "Visual Studio 2015"),
    (21005, "Visual Studio 2013"),
    (0, "Visual Studio 2012 or earlier"),
)
_GO_BUILDINFO = b"\xff Go buildinf:"


def toolchain_hints(analysis, data: bytes) -> tuple[ToolchainHint, ...]:
    hints: list[ToolchainHint] = []
    add = lambda name, evidence: hints.append(ToolchainHint(name, evidence))  # noqa: E731
    names = {section.name for section in analysis.sections}
    strings = analysis.strings

    def has_string(*needles: str) -> str | None:
        for value in strings:
            for needle in needles:
                if needle in value:
                    return value[:80]
        return None

    if {"UPX0", "UPX1"} & names or b"UPX!" in data[:4096]:
        add("UPX packer", "UPX0/UPX1 sections" if {"UPX0", "UPX1"} & names else "UPX! marker in the headers")
    if any(name.startswith((".vmp", "vmp")) for name in names):
        add("VMProtect", "a .vmp section")
    if any(name.lower() in (".themida", ".winlice") for name in names):
        add("Themida / WinLicense", "a .themida or .winlicense section")
    if ".aspack" in names or ".adata" in names:
        add("ASPack", "an .aspack/.adata section")
    if "MPRESS1" in names or ".MPRESS1" in names:
        add("MPRESS packer", "an MPRESS1 section")
    if analysis.clr_info is not None:
        add(".NET", "a CLR runtime header")
    overlay = analysis.overlay
    if overlay is not None and overlay.container:
        add(overlay.container, f"marker in the overlay at 0x{overlay.container_offset:X}")
    if (overlay is None or overlay.container != "PyInstaller archive") and has_string("_MEIPASS", "PyInstaller"):
        add("PyInstaller", "PyInstaller strings")
    evidence = has_string("Nuitka", "__nuitka")
    if evidence:
        add("Nuitka (Python compiled to C)", f"string {evidence!r}")
    position = data.find(_GO_BUILDINFO)
    if position != -1:
        add("Go", f"Go build info at 0x{position:X}")
    evidence = has_string("/rustc/", "\\rustc\\", "rust_panic", "rust_begin_unwind")
    if evidence:
        add("Rust", f"string {evidence!r}")
    if {"CODE", "DATA", "BSS"} <= names or any(
        resource.type == "10" and resource.name in ("DVCLAL", "PACKAGEINFO") for resource in analysis.resources
    ):
        add("Delphi / C++Builder", "CODE/DATA/BSS sections or DVCLAL/PACKAGEINFO resources")
    if b"AU3!EA06" in data or any(resource.name == "SCRIPT" and resource.type == "10" for resource in analysis.resources):
        add("AutoIt script", "AU3!EA06 marker or a SCRIPT resource")
    evidence = has_string("GCC: (", "mingw", "MinGW")
    if evidence:
        add("GCC / MinGW", f"string {evidence!r}")
    security = analysis.security
    if security is not None and security.rich_header:
        build = max(entry.build for entry in security.rich_header)
        release = next(name for minimum, name in _MSVC_BUILDS if build >= minimum)
        add(f"Microsoft linker ({release})", f"Rich header, highest tool build {build}")
    return tuple(hints)


# ---- string categories (F5) -------------------------------------------------------------------

STRING_CATEGORIES = ("url", "ip", "email", "registry", "path", "base64")
_STRING_PATTERNS = (
    ("url", re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{3,}", re.IGNORECASE)),
    ("ip", re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])")),
    ("email", re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")),
    ("registry", re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\|\b(?:SOFTWARE|SYSTEM)\\(?:Microsoft|CurrentControlSet|Classes|Policies)\\", re.IGNORECASE)),
    ("path", re.compile(r"\b[A-Za-z]:\\[\w$ .()-]{3,}|\\\\[\w.$-]{2,}\\[\w$.-]|%[A-Za-z]+%\\")),
    ("base64", re.compile(r"^(?=[A-Za-z0-9+/]*[0-9+/])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[A-Z])(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")),
)


def string_category(value: str) -> str:
    """The first matching category in STRING_CATEGORIES order, or "" for an ordinary string."""
    for name, pattern in _STRING_PATTERNS:
        if not pattern.search(value):
            continue
        if name == "ip" and _VERSION_LIKE.search(value):
            continue  # 4.0.0.0, version="5.1.0.0": a version number, not an address
        if name == "base64" and len(value) < 40 and not re.search(r"[+/=]", value):
            continue  # CreateToolhelp32Snapshot: an identifier, not encoded data
        return name
    return ""


_VERSION_LIKE = re.compile(r"^\d+\.\d+\.\d+\.0$|version", re.IGNORECASE)
