"""Optional YARA scanning (F2) with rules the user supplies. Needs the yara-python package, which
is not a dependency: without it the scan reports how to install it. The file's bytes are matched
in memory, with a time limit and capped output; nothing is executed or sent anywhere."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

RULE_SUFFIXES = (".yar", ".yara")
MAX_RULE_FILES = 500
MAX_MATCHES = 500
MAX_STRINGS_PER_MATCH = 20
DEFAULT_TIMEOUT = 60  # seconds


class YaraError(RuntimeError):
    pass


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]
    strings: tuple[str, ...]  # "$identifier at 0xOFFSET"


def _yara():
    try:
        import yara
    except ImportError as exc:
        raise YaraError(
            "YARA scanning needs the yara-python package: python -m pip install yara-python"
        ) from exc
    return yara


def rule_files(rules: str | Path) -> dict[str, str]:
    """{namespace: path} for one rules file, or every .yar/.yara file in a folder (recursively)."""
    rules = Path(rules)
    if rules.is_file():
        return {rules.stem: str(rules)}
    if rules.is_dir():
        found = sorted(path for path in rules.rglob("*") if path.suffix.lower() in RULE_SUFFIXES)
        if not found:
            raise YaraError(f"No .yar or .yara files in {rules}.")
        if len(found) > MAX_RULE_FILES:
            raise YaraError(f"More than {MAX_RULE_FILES} rule files in {rules}.")
        return {str(path.relative_to(rules).with_suffix("")).replace("\\", "/"): str(path) for path in found}
    raise YaraError(f"{rules} is not a rules file or folder.")


def _strings(match) -> tuple[str, ...]:
    found = []
    for item in getattr(match, "strings", ()):
        if isinstance(item, tuple):  # yara-python < 4.3: (offset, identifier, data)
            found.append(f"{item[1]} at 0x{item[0]:X}")
        else:  # 4.3+: StringMatch with instances
            for instance in item.instances[:MAX_STRINGS_PER_MATCH]:
                found.append(f"{item.identifier} at 0x{instance.offset:X}")
        if len(found) >= MAX_STRINGS_PER_MATCH:
            break
    return tuple(found[:MAX_STRINGS_PER_MATCH])


def scan_bytes(data: bytes, rules: str | Path, timeout: int = DEFAULT_TIMEOUT) -> list[YaraMatch]:
    yara = _yara()
    try:
        compiled = yara.compile(filepaths=rule_files(rules))
        matches = compiled.match(data=data, timeout=timeout)
    except yara.TimeoutError as exc:
        raise YaraError(f"The YARA scan took longer than {timeout} s.") from exc
    except yara.Error as exc:
        raise YaraError(f"YARA: {exc}") from exc
    return [
        YaraMatch(
            match.rule,
            match.namespace,
            tuple(match.tags),
            {key: value if isinstance(value, (str, int, float, bool)) else str(value) for key, value in match.meta.items()},
            _strings(match),
        )
        for match in matches[:MAX_MATCHES]
    ]


def scan_file(path: str | Path, rules: str | Path, timeout: int = DEFAULT_TIMEOUT) -> list[YaraMatch]:
    from .pe import MAX_FILE_BYTES

    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise YaraError("The file is larger than the analysis size limit.")
    return scan_bytes(data, rules, timeout)


def matches_to_dict(matches: list[YaraMatch], rules: str | Path) -> dict[str, Any]:
    return {"rules": str(rules), "match_count": len(matches), "matches": [asdict(match) for match in matches]}


def format_matches(result: dict[str, Any]) -> str:
    lines = ["", f"YARA SCAN ({result['rules']})", "=" * 72]
    if not result["matches"]:
        return "\n".join(lines + ["No rule matched."])
    lines.append(f"{result['match_count']} rule(s) matched. A match is a pattern hit, not a verdict.")
    for match in result["matches"]:
        tags = f" [{', '.join(match['tags'])}]" if match["tags"] else ""
        lines.append(f"{match['namespace']}:{match['rule']}{tags}")
        description = match["meta"].get("description")
        if description:
            lines.append(f"  {description}")
        lines.extend(f"  {item}" for item in match["strings"])
    return "\n".join(lines)
