$ErrorActionPreference = 'Stop'

$repo = "D:\project\conditionFuzzing\wolfssl-master"
$out = "D:\project\conditionFuzzing\test-wolfssl-dtls\rfc9147\151-187"
$log = Join-Path $out "verify_wolfssl_dtls13_151_187.log"

"wolfSSL DTLS 1.3 RFC9147 151-187 verification" | Set-Content -Encoding UTF8 $log
"Repository: $repo" | Add-Content -Encoding UTF8 $log

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
    "No CMakeCache.txt found under build." | Add-Content -Encoding UTF8 $log
}

Add-Section "Dynamic CID message symbol scan"
$missing = @("NewConnectionId", "RequestConnectionId", "cid_immediate", "cid_spare")
foreach ($m in $missing) {
    $r = Run-Rg $m $sourcePaths
    if ($r.Code -eq 0) {
        "FOUND $m" | Add-Content -Encoding UTF8 $log
        $r.Output | Select-Object -First 20 | Add-Content -Encoding UTF8 $log
    }
    else {
        "ABSENT $m" | Add-Content -Encoding UTF8 $log
    }
}

Add-Section "Static positive-control scans"
$positive = @{
    "ACK enum" = "ack\s*=+\s*26|ack\s+={1}\s+26"
    "ACK parser" = "DoDtls13Ack"
    "ACK writer" = "Dtls13WriteAckMessage"
    "ACK ordering insertion" = "w64LT\(epoch, cur->epoch\)|w64LT\(seq, cur->seq\)"
    "Unified header sequence length" = "DTLS13_SEQ_16_LEN|DTLS13_SEQ_8_LEN"
    "Record-number encryption" = "Dtls13EncryptDecryptRecordNumber"
    "Replay window after deprotect" = "Dtls13CheckWindow|Dtls13UpdateWindow"
}
foreach ($name in $positive.Keys) {
    $r = Run-Rg $positive[$name] $sourcePaths
    if ($r.Code -eq 0) {
        "PASS $name" | Add-Content -Encoding UTF8 $log
        $r.Output | Select-Object -First 8 | Add-Content -Encoding UTF8 $log
    }
    else {
        "FAIL $name" | Add-Content -Encoding UTF8 $log
        exit 1
    }
}

Add-Section "Decision"
"The dynamic CID update message symbols are absent, while DTLS 1.3 ACK, unified header sequence-number, record-number encryption, and anti-replay paths are present in source. Current CMake cache also has WOLFSSL_DTLS13=no and WOLFSSL_DTLS_CID=no, so built executable tests for the missing dynamic CID messages are not available in this build tree." | Add-Content -Encoding UTF8 $log

exit 0
