"""Import bounded, normalized reports from an independently isolated sandbox."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_SANDBOX_REPORT_BYTES = 5 * 1024 * 1024
MAX_SANDBOX_EVENTS = 5000
MAX_FIELD_LENGTH = 2000
_CATEGORIES = {"process", "file", "registry", "network", "other"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SandboxReportError(ValueError):
    """Raised when an imported behavior report is invalid or too large."""


@dataclass(frozen=True)
class SandboxEvent:
    category: str
    action: str
    target: str
    details: str
    timestamp: str


@dataclass(frozen=True)
class SandboxReport:
    schema: str
    source_sha256: str | None
    events: tuple[SandboxEvent, ...]
    source_hash_matches: bool | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=True)


def _text(value: object, field: str, *, required: bool = False) -> str:
    if not isinstance(value, str):
        if required:
            raise SandboxReportError(f"Sandbox event field {field!r} must be a string.")
        return ""
    cleaned = "".join(char for char in value if char.isprintable() or char in "\t")
    if required and not cleaned.strip():
        raise SandboxReportError(f"Sandbox event field {field!r} cannot be empty.")
    return cleaned[:MAX_FIELD_LENGTH]


def parse_sandbox_report(data: bytes, analyzed_sha256: str | None = None) -> SandboxReport:
    if len(data) > MAX_SANDBOX_REPORT_BYTES:
        raise SandboxReportError("Sandbox reports are limited to 5 MiB.")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxReportError("The sandbox report must be valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict) or payload.get("schema") != "binary-inspector-sandbox-v1":
        raise SandboxReportError("Unsupported sandbox report schema.")
    source_hash = payload.get("source_sha256")
    if source_hash is not None and (
        not isinstance(source_hash, str) or not _SHA256.fullmatch(source_hash.lower())
    ):
        raise SandboxReportError("source_sha256 must be a 64-character hexadecimal SHA-256.")
    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or len(raw_events) > MAX_SANDBOX_EVENTS:
        raise SandboxReportError(f"events must be a list of at most {MAX_SANDBOX_EVENTS} records.")

    events: list[SandboxEvent] = []
    for index, event in enumerate(raw_events):
        if not isinstance(event, dict):
            raise SandboxReportError(f"Sandbox event {index} must be a JSON object.")
        category = _text(event.get("category"), "category", required=True).lower()
        if category not in _CATEGORIES:
            raise SandboxReportError(f"Unsupported sandbox event category: {category!r}.")
        events.append(
            SandboxEvent(
                category=category,
                action=_text(event.get("action"), "action", required=True),
                target=_text(event.get("target"), "target"),
                details=_text(event.get("details"), "details"),
                timestamp=_text(event.get("timestamp"), "timestamp"),
            )
        )

    match = None
    if source_hash is not None and analyzed_sha256 is not None:
        match = source_hash.lower() == analyzed_sha256.lower()
    return SandboxReport(
        schema="binary-inspector-sandbox-v1",
        source_sha256=source_hash.lower() if source_hash else None,
        events=tuple(events),
        source_hash_matches=match,
    )


def load_sandbox_report(path: str | Path, analyzed_sha256: str | None = None) -> SandboxReport:
    report_path = Path(path)
    try:
        size = report_path.stat().st_size
        if size > MAX_SANDBOX_REPORT_BYTES:
            raise SandboxReportError("Sandbox reports are limited to 5 MiB.")
        with report_path.open("rb") as handle:
            data = handle.read(MAX_SANDBOX_REPORT_BYTES + 1)
    except OSError as exc:
        raise SandboxReportError(f"Could not read the sandbox report: {exc}") from exc
    return parse_sandbox_report(data, analyzed_sha256)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
