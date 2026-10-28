"""Command-line and desktop entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .external_tools import ToolError, decompile_dotnet, disassemble_native
from .pe import PEFormatError, analyze_file
from .sandbox_report import SandboxReportError, load_sandbox_report
from .signature import verify_authenticode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="binary-inspector",
        description="Inspect Windows PE metadata without executing the selected file.",
    )
    parser.add_argument("file", nargs="?", help="Path to a local .exe or .dll; omit to open the desktop UI.")
    parser.add_argument("--json", dest="json_path", help="Write the JSON report to this path instead of stdout.")
    parser.add_argument(
        "--disassemble",
        action="store_true",
        help="Run locally installed Rizin on the file (static analysis; never launches the sample).",
    )
    parser.add_argument(
        "--decompile-dotnet",
        action="store_true",
        help="Run locally installed ILSpyCmd to emit .NET IL (static analysis only).",
    )
    parser.add_argument(
        "--verify-signature",
        action="store_true",
        help="Ask Windows trust policy to verify the Authenticode signature (cached data only).",
    )
    parser.add_argument(
        "--sandbox-report",
        help="Import a normalized JSON behavior report exported by an isolated external sandbox.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Check packaged application imports and exit without opening the GUI.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        if (
            args.file
            or args.json_path
            or args.disassemble
            or args.decompile_dotnet
            or args.verify_signature
            or args.sandbox_report
        ):
            parser.error("--self-test cannot be combined with analysis options")
        return 0
    if args.file is None:
        if (
            args.json_path
            or args.disassemble
            or args.decompile_dotnet
            or args.verify_signature
            or args.sandbox_report
        ):
            parser.error("Analysis options require an input file")
        from .gui import run_gui

        run_gui()
        return 0

    try:
        analysis = analyze_file(args.file)
        report_data = analysis.to_dict()
        extensions = {}
        if args.disassemble:
            result = disassemble_native(args.file)
            extensions["native_disassembly"] = {
                "tool": result.tool,
                "output": result.output,
                "truncated": result.truncated,
            }
        if args.decompile_dotnet:
            result = decompile_dotnet(args.file)
            extensions["dotnet_il"] = {
                "tool": result.tool,
                "output": result.output,
                "truncated": result.truncated,
            }
        if args.verify_signature:
            extensions["authenticode_verification"] = verify_authenticode(args.file).to_dict()
        if args.sandbox_report:
            sandbox = load_sandbox_report(args.sandbox_report, analysis.sha256)
            extensions["sandbox_behavior"] = sandbox.to_dict()
        if extensions:
            report_data["extended_analysis"] = extensions
        report = json.dumps(report_data, indent=2, ensure_ascii=True) + "\n"
        if args.json_path:
            Path(args.json_path).write_text(report, encoding="utf-8")
        else:
            sys.stdout.write(report)
    except (PEFormatError, ToolError, SandboxReportError, OSError) as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
