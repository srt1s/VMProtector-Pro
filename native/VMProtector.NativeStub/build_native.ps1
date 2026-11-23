$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $scriptDir "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$vsPath = & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw "Visual Studio C++ x64 toolchain not found."
}

$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
$batFile = Join-Path $outDir "_compile_native.bat"

$batContent = @"
@echo off
call "$vcvars" >nul
if errorlevel 1 exit /b 1

cl.exe /nologo /std:c++20 /O2 /MT /EHsc /W4 "$scriptDir\main_stub.cpp" /Fe:"$outDir\VMProtector.NativeStub.Console.exe" /Fo:"$outDir\stub_con.obj" /link /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 2

cl.exe /nologo /std:c++20 /O2 /MT /EHsc /W4 /DVMP_GUI_SUBSYSTEM "$scriptDir\main_stub.cpp" /Fe:"$outDir\VMProtector.NativeStub.Gui.exe" /Fo:"$outDir\stub_gui.obj" /link /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
if errorlevel 1 exit /b 3

cl.exe /nologo /std:c++20 /O2 /GS- /Oi /c "$scriptDir\pic_guard.cpp" /Fo:"$outDir\pic_guard.obj"
if errorlevel 1 exit /b 4
"@

Set-Content -Path $batFile -Value $batContent -Encoding ASCII
cmd.exe /c "`"$batFile`""
if ($LASTEXITCODE -ne 0) {
    throw "Native C++20 compilation failed with code $LASTEXITCODE"
}

$pyScript = @'
import struct, pathlib, sys

obj_path = pathlib.Path(sys.argv[1])
hex_out = pathlib.Path(sys.argv[2])
data = obj_path.read_bytes()
machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack_from('<HHIIIHH', data, 0)
assert machine == 0x8664, f'Unexpected machine {hex(machine)}'

offset = 20 + opt_hdr_size
found = None
for _ in range(num_sections):
    name_raw, virt_size, virt_addr, raw_size, raw_ptr, reloc_ptr, _, num_relocs, _, chars = struct.unpack_from('<8sIIIIIIHHI', data, offset)
    offset += 40
    name = name_raw.split(b'\x00', 1)[0].decode(errors='ignore')
    if name in ('.text$mn', '.text') and raw_size > 0:
        assert num_relocs == 0, f'PIC guard section {name} has {num_relocs} relocations!'
        found = data[raw_ptr:raw_ptr + raw_size]
        break

assert found and len(found) > 16, 'Failed to locate PIC .text section in pic_guard.obj'
hex_out.write_text(found.hex(), encoding='utf-8')
print(f'PIC_GUARD_OK bytes={len(found)}')
'@

python -c $pyScript "$outDir\pic_guard.obj" "$outDir\pic_guard_x64.hex"
if ($LASTEXITCODE -ne 0) {
    throw "PIC extraction failed with code $LASTEXITCODE"
}

Write-Output "NATIVE_BUILD_COMPLETE"
Get-ChildItem $outDir | Select-Object Name, Length