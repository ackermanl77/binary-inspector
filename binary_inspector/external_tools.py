"""Bounded integrations with locally installed static-analysis tools."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

MAX_TOOL_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 180


class ToolError(RuntimeError):
    """Raised when an optional local analysis tool cannot complete safely."""


@dataclass(frozen=True)
class ToolResult:
    tool: str
    output: str
    truncated: bool


def _resolve_tool(env_name: str, executable_name: str) -> str:
    configured = os.environ.get(env_name, "").strip()
    executable = configured or shutil.which(executable_name)
    if not executable:
        raise ToolError(
            f"{executable_name} was not found. Install it locally or set {env_name} to its executable path."
        )
    if configured and not Path(configured).is_file():
        raise ToolError(f"The configured tool path does not exist: {configured}")
    return executable


def _run_bounded(
    executable: str,
    arguments: list[str],
    input_path: str | os.PathLike[str],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ToolResult:
    source = Path(input_path).resolve(strict=True)
    if not source.is_file():
        raise ToolError("The selected input is not a regular file.")
    if timeout_seconds < 1 or timeout_seconds > 600:
        raise ValueError("Tool timeout must be between 1 and 600 seconds.")

    command = [executable, *arguments, str(source)]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=source.parent,
            shell=False,
            creationflags=creationflags,
        )
    except OSError as exc:
        raise ToolError(f"Could not run the local analysis tool: {exc}") from exc

    output = bytearray()
    total_size = 0
    reader_errors: list[OSError] = []

    def collect_output() -> None:
        nonlocal total_size
        assert process.stdout is not None
        try:
            while True:
                block = process.stdout.read1(64 * 1024)
                if not block:
                    return
                total_size += len(block)
                remaining = MAX_TOOL_OUTPUT_BYTES - len(output)
                if remaining > 0:
                    output.extend(block[:remaining])
        except (OSError, ValueError) as exc:
            reader_errors.append(exc)

    reader = threading.Thread(target=collect_output, name="binary-inspector-tool-output", daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout_seconds
    try:
        while process.poll() is None:
            if total_size > MAX_TOOL_OUTPUT_BYTES:
                raise ToolError(
                    f"Tool output exceeded the {MAX_TOOL_OUTPUT_BYTES // (1024 * 1024)} MiB limit."
                )
            if time.monotonic() >= deadline:
                raise ToolError(f"Analysis tool exceeded the {timeout_seconds}-second time limit.")
            time.sleep(0.05)

        exit_code = process.wait()
        reader.join(timeout=2)
        if reader.is_alive():
            raise ToolError("The analysis tool exited but kept its output stream open.")
        if reader_errors:
            raise ToolError(f"Could not read analysis tool output: {reader_errors[0]}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if reader.is_alive():
            reader.join(timeout=2)

    output_bytes = bytes(output)
    output = output_bytes.decode("utf-8", errors="replace")
    if exit_code:
        summary = output.strip()[-2000:] or f"Tool exited with code {exit_code}."
        raise ToolError(summary)
    return ToolResult(
        tool=Path(executable).name,
        output=output,
        truncated=total_size > MAX_TOOL_OUTPUT_BYTES,
    )


def disassemble_native(
    input_path: str | os.PathLike[str],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ToolResult:
    """Disassemble a native PE entry point with locally installed Rizin."""
    executable = _resolve_tool("BINARY_INSPECTOR_RIZIN", "rizin")
    return _run_bounded(
        executable,
        ["-q", "-A", "-e", "scr.color=false", "-c", "pd 500 @ entry0"],
        input_path,
        timeout_seconds=timeout_seconds,
    )


def decompile_dotnet(
    input_path: str | os.PathLike[str],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ToolResult:
    """Decompile a .NET assembly to C# with locally installed ILSpyCmd."""
    executable = _resolve_tool("BINARY_INSPECTOR_ILSPYCMD", "ilspycmd")
    return _run_bounded(
        executable,
        ["--disable-updatecheck"],
        input_path,
        timeout_seconds=timeout_seconds,
    )
