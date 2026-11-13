param([string]$Target = "x86_64-pc-windows-msvc")
$ErrorActionPreference = "Stop"
& cargo build -p shirusu-test -p shirusu-probe --target $Target
if ($LASTEXITCODE -ne 0) { throw "corpus binaries failed to build" }
$probe = (Resolve-Path "target/$Target/debug/shirusu-probe.exe").Path
$runner = (Resolve-Path "target/$Target/debug/shirusu-test.exe").Path
$spec = (Resolve-Path "crates/shirusu-probe/tests/fixtures/corpus-file-io.json").Path
$root = "target/windows-reference-corpus/$Target"
New-Item -ItemType Directory -Force -Path $root | Out-Null
$entry = Join-Path $root ([Guid]::NewGuid().ToString())
& $probe corpus record $spec --runner $runner --out $entry --label "GitHub Actions $env:GITHUB_RUN_ID $env:GITHUB_SHA $Target" --timeout-ms 30000
if ($LASTEXITCODE -ne 0) { throw "corpus recording failed" }
& $probe corpus compare $entry $entry
if ($LASTEXITCODE -ne 0) { throw "corpus integrity comparison failed" }
