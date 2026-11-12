# Native application -> injected capture -> compare -> bundle -> standalone replay.
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$bin = Join-Path $repo "target\x86_64-pc-windows-msvc\debug"
$cli = Join-Path $bin "shirusu.exe"
$probe = Join-Path $bin "shirusu-probe.exe"
$compare = Join-Path $bin "shirusu-compare.exe"
$test = Join-Path $bin "shirusu-test.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$work = Join-Path $repo ("target\native-replay-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$source = Join-Path $repo "e2e\native\file-replay.cpp"
foreach ($side in @("left", "right")) {
    $dir = Join-Path $work $side
    New-Item -ItemType Directory $dir | Out-Null
    $value = if ($side -eq "left") { 42 } else { 43 }
    $exe = Join-Path $dir "fixture.exe"
    $compile = "`"$dev`" -arch=x64 && cl /nologo /W4 /O2 /GS- /DTEST_BYTE=$value /Fe:`"$exe`" /Fo:`"$dir\fixture.obj`" `"$source`" /link /ENTRY:entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib"
    $buildScript = Join-Path $work "build.cmd"
    @("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
    Invoke-Native { cmd /d /c $buildScript } "native replay fixture ($side)"
    Push-Location $dir
    try {
        & $cli capture --dll $dll --output (Join-Path $work "$side.trace") -- $exe
        if ($LASTEXITCODE -notin @(0,2)) { throw "capture $side failed: $LASTEXITCODE" }
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $dir "captured-file.bin"))
        if ($bytes.Length -ne 1 -or $bytes[0] -ne $value) { throw "fixture $side did not finish I/O" }
    } finally { Pop-Location }
}
$left = Join-Path $work "left.trace"
$right = Join-Path $work "right.trace"
$diff = & $compare $left $right --json
if ($LASTEXITCODE -ne 1) { throw "expected a recorded data difference" }
$report = ($diff -join "`n") | ConvertFrom-Json
$index = -1
for ($i = 0; $i -lt $report.candidates.Count; $i++) {
    if ($report.candidates[$i].api -eq "kernel32!ReadFile" -and $report.candidates[$i].field -eq "data") { $index = $i; break }
}
if ($index -lt 0) { throw "missing ReadFile.data candidate: $diff" }
$bundle = Join-Path $work "bundle"
Invoke-Native { & $probe $left $right --candidate $index --out $bundle } "capture-to-bundle"
$rules = Join-Path $bundle "rules.json"
Invoke-Native { & $test $left $rules } "baseline discrimination"
& $test $right $rules
if ($LASTEXITCODE -ne 1) { throw "candidate must fail the generated rule" }
$spec = Join-Path $bundle "replay.json"
if (-not (Test-Path $spec)) {
    throw "replay prerequisites failed: $(Get-Content (Join-Path $bundle 'manifest.json') -Raw)"
}
$replay = Join-Path $work "replay.exe"
Invoke-Native { & $test probe-exe $spec --target x86_64-pc-windows-msvc --out $replay } "recorded probe build"
foreach ($mode in @("exe", "runner")) {
    $dir = Join-Path $work $mode
    New-Item -ItemType Directory $dir | Out-Null
    Push-Location $dir
    try {
        if ($mode -eq "exe") { Invoke-Native { & $replay } "recorded probe execution" }
        else { Invoke-Native { & $test run $spec --json } "recorded runner execution" }
        if ([System.IO.File]::ReadAllBytes((Join-Path $dir "shirusu-replay-0.bin"))[0] -ne 42) { throw "replayed data differs" }
    } finally { Pop-Location }
}
Write-Host "Native capture -> difference -> rule -> replay passed ($work)"
