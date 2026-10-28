"""Optional Windows Authenticode trust checks; this never launches the analyzed file.

A file is checked for an embedded signature first. Most Windows system files carry none and are
signed through a security catalog instead, so an unsigned result is followed by a catalog lookup
(the file is only read, to hash it) and, when a catalog lists the file, catalog verification.
"""

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
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = uuid.UUID("00AAC56B-CD44-11D0-8CC2-00C04FC295EE")
_DRIVER_ACTION_VERIFY = uuid.UUID("F750E6C3-38EE-11D1-85E5-00C04FC295EE")
_WTD_CHOICE_FILE = 1
_WTD_CHOICE_CATALOG = 2
# Catalogs are hashed with SHA-256 on current Windows and SHA-1 on older ones (None = SHA-1).
_CATALOG_HASH_ALGORITHMS = ("SHA256", None)


@dataclass(frozen=True)
class SignatureVerification:
    status: str
    status_code: int | None
    detail: str
    source: str | None = None  # "embedded" or "catalog" when a signature was found
    signer: str | None = None
    issuer: str | None = None
    catalog: str | None = None  # the catalog file that lists this file

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _status_for_result(
    result: int,
    source: str | None = None,
    signer: str | None = None,
    issuer: str | None = None,
    catalog: str | None = None,
) -> SignatureVerification:
    code = result & 0xFFFFFFFF
    found = {"source": source, "signer": signer, "issuer": issuer, "catalog": catalog}
    if code == 0:
        where = "the file's catalog signature" if source == "catalog" else "the signature"
        return SignatureVerification(
            "trusted",
            code,
            f"Windows trust policy accepted {where}. Revocation was not checked; URL retrieval was disabled.",
            **found,
        )
    if code == _TRUST_E_NOSIGNATURE:
        return SignatureVerification(
            "unsigned",
            code,
            "Windows found no embedded Authenticode signature and no system catalog listing this file.",
        )
    if code in _UNTRUSTED_STATUSES:
        return SignatureVerification(
            "untrusted",
            code,
            "Windows rejected the signature or certificate chain. This is not a malware verdict.",
            **found,
        )
    return SignatureVerification(
        "unable_to_verify",
        code,
        "Windows could not complete trust verification. Review the status code and system trust configuration.",
        **found,
    )


class _Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def of(cls, value: uuid.UUID) -> "_Guid":
        return cls.from_buffer_copy(value.bytes_le)


class _WinTrustFileInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_Guid)),
    ]


class _WinTrustCatalogInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wintypes.HANDLE),
    ]


class _WinTrustData(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pUnion", ctypes.c_void_p),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class _CryptProviderCert(ctypes.Structure):
    # Only the leading fields are read.
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class _CatalogInfo(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]


def _certificate_name(crypt32, certificate: int, issuer: bool) -> str | None:
    get_name = crypt32.CertGetNameStringW
    get_name.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD
    ]
    get_name.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(512)
    flags = 1 if issuer else 0  # CERT_NAME_ISSUER_FLAG
    length = get_name(certificate, 4, flags, None, buffer, len(buffer))  # CERT_NAME_SIMPLE_DISPLAY_TYPE
    return buffer.value if length > 1 and buffer.value else None


def _signer_names(trust, state) -> tuple[str | None, str | None]:
    """The leaf signing certificate's subject and issuer from a verified trust state."""
    provider_data = trust.WTHelperProvDataFromStateData
    provider_data.argtypes = [wintypes.HANDLE]
    provider_data.restype = ctypes.c_void_p
    signer_from_chain = trust.WTHelperGetProvSignerFromChain
    signer_from_chain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    signer_from_chain.restype = ctypes.c_void_p
    cert_from_chain = trust.WTHelperGetProvCertFromChain
    cert_from_chain.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    cert_from_chain.restype = ctypes.POINTER(_CryptProviderCert)

    provider = provider_data(state) if state else None
    signer = signer_from_chain(provider, 0, False, 0) if provider else None
    certificate = cert_from_chain(signer, 0) if signer else None
    if not certificate or not certificate.contents.pCert:
        return None, None
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    leaf = certificate.contents.pCert
    return _certificate_name(crypt32, leaf, False), _certificate_name(crypt32, leaf, True)


def _win_verify_trust(trust, union_choice: int, union) -> tuple[int, str | None, str | None]:
    """WinVerifyTrust (no UI, no revocation, cached URL data only) and the signer it found."""
    action = _Guid.of(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
    data = _WinTrustData(
        ctypes.sizeof(_WinTrustData),
        None,
        None,
        2,  # WTD_UI_NONE
        0,  # WTD_REVOKE_NONE
        union_choice,
        ctypes.cast(ctypes.pointer(union), ctypes.c_void_p),
        1,  # WTD_STATEACTION_VERIFY
        None,
        None,
        0x1000,  # WTD_CACHE_ONLY_URL_RETRIEVAL: never fetch from the network
        0,
        None,
    )
    verify = trust.WinVerifyTrust
    verify.argtypes = [wintypes.HWND, ctypes.POINTER(_Guid), ctypes.POINTER(_WinTrustData)]
    verify.restype = ctypes.c_long
    signer = issuer = None
    try:
        result = verify(ctypes.c_void_p(-1), ctypes.byref(action), ctypes.byref(data))
        if (result & 0xFFFFFFFF) != _TRUST_E_NOSIGNATURE:
            signer, issuer = _signer_names(trust, data.hWVTStateData)
    finally:
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        verify(ctypes.c_void_p(-1), ctypes.byref(action), ctypes.byref(data))
    return result, signer, issuer


def _verify_catalog(trust, path: Path) -> SignatureVerification | None:
    """Verification against the system catalog that lists the file's hash; None if none does."""
    import msvcrt

    acquire = trust.CryptCATAdminAcquireContext2
    acquire.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(_Guid), wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD
    ]
    acquire.restype = wintypes.BOOL
    release = trust.CryptCATAdminReleaseContext
    release.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    calc_hash = trust.CryptCATAdminCalcHashFromFileHandle2
    calc_hash.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD
    ]
    calc_hash.restype = wintypes.BOOL
    enum_catalog = trust.CryptCATAdminEnumCatalogFromHash
    enum_catalog.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    enum_catalog.restype = wintypes.HANDLE
    release_catalog = trust.CryptCATAdminReleaseCatalogContext
    release_catalog.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    catalog_info = trust.CryptCATCatalogInfoFromContext
    catalog_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_CatalogInfo), wintypes.DWORD]
    catalog_info.restype = wintypes.BOOL

    policy = _Guid.of(_DRIVER_ACTION_VERIFY)
    for algorithm in _CATALOG_HASH_ALGORITHMS:
        admin = wintypes.HANDLE()
        if not acquire(ctypes.byref(admin), ctypes.byref(policy), algorithm, None, 0):
            continue
        try:
            with open(path, "rb") as stream:
                handle = msvcrt.get_osfhandle(stream.fileno())
                size = wintypes.DWORD(0)
                calc_hash(admin, handle, ctypes.byref(size), None, 0)
                if not size.value or size.value > 64:
                    continue
                digest = (ctypes.c_ubyte * size.value)()
                if not calc_hash(admin, handle, ctypes.byref(size), digest, 0):
                    continue
            context = enum_catalog(admin, digest, size, 0, None)
            if not context:
                continue
            try:
                info = _CatalogInfo(ctypes.sizeof(_CatalogInfo))
                if not catalog_info(context, ctypes.byref(info), 0):
                    continue
                member = _WinTrustCatalogInfo(
                    ctypes.sizeof(_WinTrustCatalogInfo),
                    0,
                    info.wszCatalogFile,
                    bytes(digest).hex().upper(),
                    str(path),
                    None,
                    ctypes.cast(digest, ctypes.POINTER(ctypes.c_ubyte)),
                    size.value,
                    None,
                    admin,
                )
                result, signer, issuer = _win_verify_trust(trust, _WTD_CHOICE_CATALOG, member)
                return _status_for_result(result, "catalog", signer, issuer, info.wszCatalogFile)
            finally:
                release_catalog(admin, context, 0)
        finally:
            release(admin, 0)
    return None


def _verify_windows(path: Path) -> SignatureVerification:
    trust = ctypes.WinDLL("wintrust", use_last_error=True)
    file_info = _WinTrustFileInfo(ctypes.sizeof(_WinTrustFileInfo), str(path), None, None)
    result, signer, issuer = _win_verify_trust(trust, _WTD_CHOICE_FILE, file_info)
    if (result & 0xFFFFFFFF) == _TRUST_E_NOSIGNATURE:
        catalog = _verify_catalog(trust, path)
        if catalog is not None:
            return catalog
    return _status_for_result(result, "embedded", signer, issuer)


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
