$ErrorActionPreference = 'Stop'

$out = $PSScriptRoot
$workspace = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$repo = Resolve-Path (Join-Path $workspace "wolfssl-master")
$repoPath = $repo.Path
$log = Join-Path $out "verify_wolfssl_dtls13_151_187.log"

"wolfSSL DTLS 1.3 RFC9147 151-187 verification" | Set-Content -Encoding UTF8 $log
"Repository: wolfssl-master" | Add-Content -Encoding UTF8 $log

function Add-Section($name) {
    "" | Add-Content -Encoding UTF8 $log
    "== $name ==" | Add-Content -Encoding UTF8 $log
}

function Run-Rg($pattern, $paths) {
    $args = @("-n", $pattern) + $paths
    $result = & rg @args 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Code = $code; Output = $result }
}

function Run-RgFixed($pattern, $paths) {
    $args = @("-n", "--fixed-strings", $pattern) + $paths
    $result = & rg @args 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Code = $code; Output = $result }
}

function Normalize-Output($lines) {
    $escapedRepo = [regex]::Escape($repoPath)
    $lines | ForEach-Object {
        ($_ -replace $escapedRepo, "wolfssl-master") -replace "\\", "/"
    }
}

$sourcePaths = @(
    (Join-Path $repo "src"),
    (Join-Path $repo "wolfssl"),
    (Join-Path $repo "tests")
)

Add-Section "Build feature flags"
$cache = Join-Path $repo "build\CMakeCache.txt"
if (Test-Path $cache) {
    $flags = Select-String -Path $cache -Pattern "WOLFSSL_DTLS13|WOLFSSL_DTLS_CID"
    $flags | ForEach-Object { $_.Line } | Add-Content -Encoding UTF8 $log
}
else {
    "No CMakeCache.txt found under wolfssl-master/build." | Add-Content -Encoding UTF8 $log
}

Add-Section "Dynamic CID message symbol scan"
$missing = @(
    "request_connection_id",
    "new_connection_id",
    "RequestConnectionId",
    "NewConnectionId",
    "ConnectionIdUsage",
    "cid_spare",
    "cid_immediate",
    "num_cids",
    "too_many_cids_requested"
)
foreach ($m in $missing) {
    $r = Run-RgFixed $m $sourcePaths
    if ($r.Code -eq 0) {
        "FOUND $m" | Add-Content -Encoding UTF8 $log
        Normalize-Output ($r.Output | Select-Object -First 20) |
            Add-Content -Encoding UTF8 $log
    }
    else {
        "ABSENT $m" | Add-Content -Encoding UTF8 $log
    }
}

Add-Section "Static CID positive-control scans"
$positive = @{
    "CIDInfo current-CID storage" = "ConnectionID\* tx;|ConnectionID\* rx;"
    "connection_id extension parser" = "TLSX_ConnectionID_Parse"
    "DTLS 1.3 unified header adds CID" = "\*flags \|= DTLS13_CID_BIT"
    "DTLS 1.3 unified header checks CID" = "DtlsCIDCheck\(ssl"
    "CID API rejects in-connection CID changes" = "doesn't support changing the CID during a"
}
foreach ($name in $positive.Keys) {
    $r = Run-Rg $positive[$name] $sourcePaths
    if ($r.Code -eq 0) {
        "PASS $name" | Add-Content -Encoding UTF8 $log
        Normalize-Output ($r.Output | Select-Object -First 4) |
            Add-Content -Encoding UTF8 $log
    }
    else {
        "FAIL $name" | Add-Content -Encoding UTF8 $log
        exit 1
    }
}

Add-Section "Dispatcher checks"
$tls13 = Get-Content -Path (Join-Path $repo "src\tls13.c") -Raw
$dispatcherStart = $tls13.IndexOf("int DoTls13HandShakeMsgType(")
$dispatcherEnd = $tls13.IndexOf("#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_ASYNC_IO)", $dispatcherStart)
$dispatcher = $tls13.Substring($dispatcherStart, $dispatcherEnd - $dispatcherStart)
if ($dispatcher.Contains("ret = UNKNOWN_HANDSHAKE_TYPE;")) {
    "PASS dispatcher unknown-message fallback returns UNKNOWN_HANDSHAKE_TYPE" | Add-Content -Encoding UTF8 $log
}
else {
    "FAIL dispatcher unknown-message fallback was not found" | Add-Content -Encoding UTF8 $log
    exit 1
}
foreach ($caseName in @("case request_connection_id", "case new_connection_id")) {
    if ($dispatcher.Contains($caseName)) {
        "FOUND $caseName" | Add-Content -Encoding UTF8 $log
        exit 1
    }
    else {
        "ABSENT $caseName" | Add-Content -Encoding UTF8 $log
    }
}

Add-Section "Decision"
"PASS dynamic CID update support is absent in wolfssl-master: the static CID extension/header paths are present, but no RequestConnectionId/NewConnectionId message types, ConnectionIdUsage values, num_cids handling, or cid_spare/cid_immediate state machine were found." | Add-Content -Encoding UTF8 $log

exit 0
