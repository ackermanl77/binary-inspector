# Changelog

All notable changes to Binary Inspector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased] -- 0.1.0, the first release

### Added
- Static, non-executing inspection of Windows PE files: headers, sections, imports and exports,
  resources and version fields, mitigations, TLS callbacks, the manifest, the overlay, debug
  records and the Rich header, with bounded parsing throughout.
- A tabbed window (Summary, Sections, Imports, Exports, Resources, Security, .NET, Strings,
  Tools, Full report) with a light, a dark and a follow-Windows theme, sortable tables and
  Ctrl+C copying.
- .NET metadata, file hashes, colour-coded hints, Compare with another file, folder batch
  analysis with a `summary.csv`, and optional YARA scanning.
- Authenticode verification, including files signed through a Windows security catalog.
- Import of sandbox behaviour reports, and optional Rizin / ILSpyCmd integration.
- An error log: an unexpected error is shown in a dialog and written to `error.log` next to
  `settings.json` (the windowed exe has no console).
- A once-per-launch update check against the project's GitHub Releases (update.json) (`update_check.py`).
- GitHub Actions CI: ruff and the tests on Python 3.10 and 3.13, then the build and its
  packaged `--self-test`. Dependabot and a `pip-audit` job watch the dependencies.
- The MIT license, `THIRD_PARTY_NOTICES.md` (shipped inside the exe), `SECURITY.md` and a
  privacy note in the README.

### Fixed
- `build.ps1` now waits for the packaged `--self-test` and checks its exit code; before, the
  windowed exe returned at once and the check always passed.
