param([ValidateSet("x86_64-pc-windows-msvc", "i686-pc-windows-msvc")][string]$Target = "x86_64-pc-windows-msvc")
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "native-step.ps1")
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$arch = if ($Target -eq "i686-pc-windows-msvc") { "x86" } else { "x64" }
$bin = Join-Path $repo "target\$Target\debug"
$cli = Join-Path $bin "shirusu.exe"
$dll = Join-Path $bin "shirusu_agent_dll.dll"
$work = Join-Path $repo ("target\native-legacy-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "MSVC compiler not found" }
$dev = Join-Path $vs "Common7\Tools\VsDevCmd.bat"
$source = Join-Path $repo "e2e\native\legacy-api.cpp"
$exe = Join-Path $work "legacy-api.exe"
$compile = "`"$dev`" -arch=$arch && cl /nologo /W4 /WX /O2 /GS- /Fe:`"$exe`" /Fo:`"$work\fixture.obj`" `"$source`" /link /ENTRY:entry /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib advapi32.lib"
$buildScript = Join-Path $work "build.cmd"
@("@echo off", "call $compile") | Set-Content -Encoding ascii $buildScript
Invoke-Native { cmd /d /c $buildScript } "legacy API fixture ($arch)"
$expected = @(
    "CreateFileA",
    "DeleteFileA",
    "MoveFileA",
    "CopyFileA",
    "CreateDirectoryA",
    "RemoveDirectoryA",
    "GetFileAttributesA",
    "SetFileAttributesA",
    "GetCurrentDirectoryA",
    "SetCurrentDirectoryA",
    "GetTempPathA",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "FindClose",
    "GetFileInformationByHandle",
    "GetFileInformationByHandleEx",
    "SetFileInformationByHandle",
    "GetFullPathNameA",
    "GetFullPathNameW",
    "GetLongPathNameA",
    "GetLongPathNameW",
    "GetShortPathNameA",
    "GetShortPathNameW",
    "GetDiskFreeSpaceExA",
    "GetDiskFreeSpaceExW",
    "GetDriveTypeA",
    "GetDriveTypeW",
    "GetLogicalDrives",
    "GetLogicalDriveStringsA",
    "GetLogicalDriveStringsW",
    "RegOpenKeyExA",
    "RegCreateKeyExA",
    "RegQueryValueExA",
    "RegSetValueExA",
    "RegDeleteValueA",
    "RegDeleteKeyA",
    "RegEnumKeyExA",
    "RegEnumValueA",
    "RegQueryInfoKeyA"
)
try {
    foreach ($mode in @("baseline", "capture")) {
        $dir = Join-Path $work $mode
        New-Item -ItemType Directory $dir | Out-Null
        Push-Location $dir
        try {
            if ($mode -eq "baseline") { Invoke-Native { & $exe } "legacy API baseline" }
            else {
                $trace = Join-Path $work "legacy.trace"
                $selection = @("capture", "--dll", $dll, "--mode", "filtered", "--output", $trace)
                foreach ($name in $expected) { $selection += @("--api", $name) }
                & $cli @selection -- $exe | Tee-Object -Variable captureOutput
                if ($LASTEXITCODE -notin @(0,2)) { throw "legacy capture failed: $LASTEXITCODE" }
                if (-not ($captureOutput -match '^target exit code: 0 \(0x00000000\)$')) { throw "legacy target did not exit successfully" }
            }
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $dir "result.bin"))
            if (($bytes -join ",") -ne "205,171,52,18") { throw "legacy application did not finish correctly ($mode)" }
        } finally { Pop-Location }
    }
    $summary = & $cli inspect $trace --json
    if ($LASTEXITCODE -ne 0) { throw "legacy trace inspection failed: $LASTEXITCODE" }
    $integrity = (($summary -join "`n") | ConvertFrom-Json).integrity
    if ($integrity.status -ne "complete" -or -not $integrity.finalized_cleanly -or $integrity.total_loss_count -ne 0) {
        throw "legacy event integrity incomplete: $summary"
    }
    $json = & $cli export $trace --format jsonl
    if ($LASTEXITCODE -ne 0) { throw "legacy trace export failed: $LASTEXITCODE" }
    $json | Set-Content (Join-Path $work "legacy.jsonl")
    $events = @($json | ForEach-Object { $_ | ConvertFrom-Json })
    foreach ($name in $expected) {
        $calls = @($events | Where-Object { $_.api -match "!$name$" -and $_.phase -eq "enter" })
        if ($calls.Count -eq 0) { throw "missing legacy API: $name" }
        foreach ($call in $calls) {
            $leaves = @($events | Where-Object {
                $_.api -eq $call.api -and $_.call_id -eq $call.call_id -and
                $_.thread_id -eq $call.thread_id -and $_.phase -eq "leave"
            })
            if ($leaves.Count -ne 1 -or $leaves[0].args_error -or $call.args_error) {
                throw "invalid enter/leave pair: $name call $($call.call_id)"
            }
        }
    }
    $failedAttributes = @($events | Where-Object {
        $_.api -eq "kernel32!GetFileAttributesA" -and $_.phase -eq "leave" -and
        $_.fields.return.value -eq 4294967295 -and $_.fields.last_error.value -eq 2 -and
        $_.fields.last_error.capture -eq "captured"
    })
    if ($failedAttributes.Count -ne 1) { throw "missing typed GetFileAttributesA failure / LastError" }
    Write-Host "Legacy API native capture passed: $($expected.Count) APIs ($arch)"
} finally {
    if ($env:SHIRUSU_DIAGNOSTIC_DIR) {
        Get-ChildItem $work -File | Where-Object { $_.Extension -in @(".trace", ".jsonl") } |
            Copy-Item -Destination $env:SHIRUSU_DIAGNOSTIC_DIR
    }
}
