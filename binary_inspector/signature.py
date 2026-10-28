"""Optional Windows Authenticode trust checks; this never launches the analyzed file."""

from __future__ import annotations

import ctypes
import os
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from ctypes import wintypes

_TRUST_E_NOSIGNATURE = 0x800B0100
_UNTRUSTED_STATUSES = {
    0x80096010,  # TRUST_E_BAD_DIGEST
    0x800B0004,  # TRUST_E_SUBJECT_NOT_TRUSTED
    0x800B0101,  # CERT_E_EXPIRED
    0x800B0109,  # CERT_E_UNTRUSTEDROOT
    0x800B010A,  # CERT_E_CHAINING
    0x800B010C,  # CERT_E_REVOKED
    0x800B0110,  # CERT_E_WRONG_USAGE
    0x800B0111,  # TRUST_E_EXPLICIT_DISTRUST
}


@dataclass(frozen=True)
class SignatureVerification:
    status: str
    status_code: int | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _status_for_result(result: int) -> SignatureVerification:
    code = result & 0xFFFFFFFF
    if code == 0:
        return SignatureVerification(
            "trusted",
            code,
            "Windows trust policy accepted the signature. Revocation was not checked; URL retrieval was disabled.",
        )
    if code == _TRUST_E_NOSIGNATURE:
        return SignatureVerification("unsigned", code, "Windows did not find an Authenticode signature.")
    if code in _UNTRUSTED_STATUSES:
        return SignatureVerification(
            "untrusted",
            code,
            "Windows rejected the signature or certificate chain. This is not a malware verdict.",
        )
    return SignatureVerification(
        "unable_to_verify",
        code,
        "Windows could not complete trust verification. Review the status code and system trust configuration.",
    )


def _verify_windows(path: Path) -> SignatureVerification:
    class Guid(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WinTrustFileInfo(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(Guid)),
        ]

    class WinTrustData(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.c_void_p),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    action_uuid = uuid.UUID("00AAC56B-CD44-11D0-8CC2-00C04FC295EE")
    action = Guid.from_buffer_copy(action_uuid.bytes_le)
    file_info = WinTrustFileInfo(
        ctypes.sizeof(WinTrustFileInfo),
        str(path),
        None,
        None,
    )
    data = WinTrustData(
        ctypes.sizeof(WinTrustData),
        None,
        None,
        2,  # WTD_UI_NONE
        0,  # WTD_REVOKE_NONE
        1,  # WTD_CHOICE_FILE
        ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p),
        1,  # WTD_STATEACTION_VERIFY
        None,
        None,
        0x1000,  # WTD_CACHE_ONLY_URL_RETRIEVAL: never fetch from the network
        0,
        None,
    )
    trust = ctypes.WinDLL("wintrust", use_last_error=True)
    verify = trust.WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(Guid), ctypes.POINTER(WinTrustData)]
    verify.restype = ctypes.c_long
    try:
        result = verify(ctypes.c_void_p(-1), ctypes.byref(action), ctypes.byref(data))
    finally:
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        verify(ctypes.c_void_p(-1), ctypes.byref(action), ctypes.byref(data))
    return _status_for_result(result)


def verify_authenticode(path: str | os.PathLike[str]) -> SignatureVerification:
    """Verify a file using cached Windows trust policy; non-Windows systems report unavailable."""
    if os.name != "nt":
        return SignatureVerification(
            "unable_to_verify",
            None,
            "Authenticode trust verification is only available on Windows.",
        )
    try:
        file_path = Path(path).resolve(strict=True)
        if not file_path.is_file():
            return SignatureVerification("unable_to_verify", None, "The selected path is not a regular file.")
        return _verify_windows(file_path)
    except (OSError, ValueError, AttributeError, ctypes.ArgumentError) as exc:
        return SignatureVerification("unable_to_verify", None, f"Windows trust verification failed: {exc}")
