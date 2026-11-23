param(
    [switch]$SkipTests,
    [switch]$SelfContained
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== [1/4] Building C++20 x64 Native VM & Reflective PE64 Stub ===" -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File (Join-Path $root "native\VMProtector.NativeStub\build_native.ps1")
if ($LASTEXITCODE -ne 0) { throw "Native stub build failed." }

Write-Host "`n=== [2/4] Building .NET Runtime, Core, CLI & GUI ===" -ForegroundColor Cyan
dotnet build (Join-Path $root "src\VMProtector.Runtime\VMProtector.Runtime.csproj") -c Release
if ($LASTEXITCODE -ne 0) { throw "Runtime build failed." }

dotnet build (Join-Path $root "src\VMProtector.Core\VMProtector.Core.csproj") -c Release -p:Platform=x64 --no-incremental
if ($LASTEXITCODE -ne 0) { throw "Core build failed." }

dotnet build (Join-Path $root "VMProtectorPro.sln") -c Release -p:Platform=x64
if ($LASTEXITCODE -ne 0) { throw "Solution build failed." }

if (-not $SkipTests) {
    Write-Host "`n=== [3/4] Running End-to-End Verification Suite ===" -ForegroundColor Cyan
    dotnet run --project (Join-Path $root "tests\VMProtector.Tests\VMProtector.Tests.csproj") -c Release -p:Platform=x64 --no-build
    if ($LASTEXITCODE -ne 0) { throw "Verification tests failed." }
}

Write-Host "`n=== [4/4] Publishing CLI & GUI Executables ===" -ForegroundColor Cyan
$distDir = Join-Path $root "release"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$scFlag = if ($SelfContained) { "true" } else { "false" }

dotnet publish (Join-Path $root "src\VMProtector.CLI\VMProtector.CLI.csproj") `
    -c Release -r win-x64 -p:Platform=x64 -p:PublishSingleFile=true --self-contained $scFlag `
    -p:DebugType=none -p:DebugSymbols=false -o $distDir
if ($LASTEXITCODE -ne 0) { throw "CLI publish failed." }

dotnet publish (Join-Path $root "src\VMProtector.GUI\VMProtector.GUI.csproj") `
    -c Release -r win-x64 -p:Platform=x64 -p:PublishSingleFile=true --self-contained $scFlag `
    -p:DebugType=none -p:DebugSymbols=false -o $distDir
if ($LASTEXITCODE -ne 0) { throw "GUI publish failed." }

Copy-Item (Join-Path $distDir "VMProtector.exe") (Join-Path $root "VMProtector.exe") -Force
Copy-Item (Join-Path $distDir "vmp-cli.exe") (Join-Path $root "vmp-cli.exe") -Force

Write-Host "`n[OK] VMProtector-Pro v2.0 Build Complete -> $distDir" -ForegroundColor Green
Get-ChildItem $distDir | Select-Object Name, Length
