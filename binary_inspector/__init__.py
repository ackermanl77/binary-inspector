"""Static inspection tools for Windows PE files."""

__version__ = "0.1.0"  # keep in step with pyproject.toml (tests/test_update_check.py checks)

from .pe import Analysis, PEFormatError, analyze_bytes, analyze_file
from .sandbox_report import SandboxReport, SandboxReportError, load_sandbox_report, parse_sandbox_report

__all__ = [
    "Analysis",
    "PEFormatError",
    "SandboxReport",
    "SandboxReportError",
    "analyze_bytes",
    "analyze_file",
    "load_sandbox_report",
    "parse_sandbox_report",
]
