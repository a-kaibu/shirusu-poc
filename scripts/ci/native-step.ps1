# ネイティブコマンドの終了コード伝播ヘルパー (レビュー #4 の #3)。
#
# $ErrorActionPreference = "Stop" は PowerShell コマンドレットのエラー
# では止まるが、ネイティブコマンド (cargo / *.exe) が非ゼロで終了しても
# 止まらない。そのため、終了コードを見ずに後続コマンドを続けると、
# 途中のテスト失敗が最後のコマンドの成功で上書きされ、ジョブ全体が
# 成功扱いになる (run #4 の windows-x64 で実際に起きた)。
#
# CI スクリプトのネイティブコマンドは全て Invoke-Native 経由で実行し、
# $LASTEXITCODE をその場で検査する。失敗したら throw してスクリプトを
# 非ゼロで終わらせる (pwsh -File の終了コードがジョブの成否になる)。
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)] [scriptblock] $Command,
        [Parameter(Mandatory = $true)] [string] $What
    )
    & $Command
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "native step failed: $What (exit code $code)"
    }
}
