"""PyInstaller entry point for the Binary Inspector desktop executable."""

from binary_inspector.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
