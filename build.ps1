$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    python -m venv (Join-Path $root ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the isolated build environment."
    }
}

& $python -m pip install -r (Join-Path $root "requirements-build.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Could not install the pinned build requirements."
}

# THIRD_PARTY_NOTICES.md lists the packages actually being bundled; the spec ships it.
& $python (Join-Path $root "scripts\third_party_notices.py")
if ($LASTEXITCODE -ne 0) {
    throw "Could not write THIRD_PARTY_NOTICES.md."
}

$arguments = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--name", "BinaryInspector",
    "--specpath", (Join-Path $root "__pyinstaller"),
    "--workpath", (Join-Path $root "__pyinstaller\work"),
    "--distpath", (Join-Path $root "dist"),
    "launcher.py"
)

& $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed."
}

$executable = Join-Path $root "dist\BinaryInspector.exe"
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Build finished without producing $executable"
}

# --windowed builds a GUI-subsystem executable, which `&` does not wait for; wait for its exit code.
$selfTest = Start-Process -FilePath $executable -ArgumentList "--self-test" -Wait -PassThru
if ($selfTest.ExitCode -ne 0) {
    throw "The packaged executable self-test failed."
}

Write-Output "Built and verified: $executable"
