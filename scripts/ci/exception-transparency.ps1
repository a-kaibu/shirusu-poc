$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
Set-Location (Join-Path $PSScriptRoot "..\..")
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$work = Join-Path $PWD "target\native-exception"
New-Item -ItemType Directory -Force $work | Out-Null
$source = Join-Path $PWD "e2e\native\exception-transparency.cpp"
$exe = Join-Path $work "exception-transparency.exe"
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$compile = "`"$dev`" -arch=x64 && cl /nologo /W4 /O2 /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`""
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "native SEH fixture build"
$baseline = Join-Path $work "baseline.txt"
$captured = Join-Path $work "captured.txt"
Remove-Item $baseline,$captured -ErrorAction SilentlyContinue
Invoke-Native { & $exe $baseline } "native SEH baseline"
$cli = Join-Path $PWD "target\x86_64-pc-windows-msvc\debug\shirusu.exe"
$dll = Join-Path $PWD "target\x86_64-pc-windows-msvc\debug\shirusu_agent_dll.dll"
$trace = Join-Path $work "exception.trace"
# Capture can report incomplete coverage (2); the application result must exist
# and match, and the trace must contain the actual aborted HeapAlloc invocation.
& $cli capture --dll $dll --output $trace -- $exe $captured
if ($LASTEXITCODE -notin @(0,2)) { throw "capture failed: $LASTEXITCODE" }
if (!(Test-Path $captured) -or (Get-Content $baseline -Raw) -cne (Get-Content $captured -Raw)) {
    throw "SEH transparency changed the application's result"
}
$events = & $cli export $trace --format jsonl
if ($LASTEXITCODE -notin @(0,2)) { throw "trace export failed" }
if (-not ($events | Where-Object { $_ -match 'HeapAlloc' -and $_ -match 'aborted' })) {
    throw "SEH fixture did not exercise an instrumented HeapAlloc abort"
}
