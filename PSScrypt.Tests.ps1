#Requires -Version 7.0
<#
.SYNOPSIS
    Independent test suite for the PSScrypt module against the official
    RFC 7914 §12 scrypt test vectors.

.DESCRIPTION
    Verifies Invoke-Scrypt produces the exact derived keys published in
    RFC 7914 (https://www.rfc-editor.org/rfc/rfc7914#section-12). These vectors
    are the canonical correctness check for any scrypt implementation and are
    independent of the Spectre/PowerPass layer that consumes this module.

    Vector #4 (N=1048576) needs ~1 GiB of RAM and takes a while; it is skipped
    by default. Pass -IncludeLargeVector to run it.

.EXAMPLE
    pwsh -File Scrypt/PSScrypt.Tests.ps1

.EXAMPLE
    pwsh -File Scrypt/PSScrypt.Tests.ps1 -IncludeLargeVector
#>
[CmdletBinding()]
param(
    [switch]$IncludeLargeVector
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'PSScrypt.psm1') -Force

Write-Host ''
Write-Host 'PSScrypt — RFC 7914 §12 scrypt test vectors' -ForegroundColor Cyan
Write-Host ('=' * 52)

[int]$pass = 0
[int]$fail = 0

function Test-Vector {
    param(
        [string]$Label,
        [string]$Password,
        [string]$Salt,
        [int]$N, [int]$R, [int]$P, [int]$DkLen,
        [string]$Expected   # hex, lowercase, no separators
    )
    [byte[]]$pw   = [Text.Encoding]::ASCII.GetBytes($Password)
    [byte[]]$salt = [Text.Encoding]::ASCII.GetBytes($Salt)

    [System.Diagnostics.Stopwatch]$sw = [System.Diagnostics.Stopwatch]::StartNew()
    [byte[]]$key = Invoke-Scrypt -Password $pw -Salt $salt -N $N -R $R -P $P -DkLen $DkLen
    $sw.Stop()

    [string]$got = ([BitConverter]::ToString($key) -replace '-').ToLower()
    if ($got -eq $Expected) {
        $script:pass++
        Write-Host ('  PASS [{0,6:F1}s]  {1}' -f $sw.Elapsed.TotalSeconds, $Label) -ForegroundColor Green
    }
    else {
        $script:fail++
        Write-Host ('  FAIL [{0,6:F1}s]  {1}' -f $sw.Elapsed.TotalSeconds, $Label) -ForegroundColor Red
        Write-Host ('         expected : {0}' -f $Expected)
        Write-Host ('         got      : {0}' -f $got)
    }
}

# RFC 7914 §12 — vector #1: scrypt("", "", 16, 1, 1, 64)
Test-Vector -Label 'scrypt("","",N=16,r=1,p=1,dkLen=64)' `
    -Password '' -Salt '' -N 16 -R 1 -P 1 -DkLen 64 `
    -Expected '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906'

# RFC 7914 §12 — vector #2: scrypt("password", "NaCl", 1024, 8, 16, 64)
Test-Vector -Label 'scrypt("password","NaCl",N=1024,r=8,p=16,dkLen=64)' `
    -Password 'password' -Salt 'NaCl' -N 1024 -R 8 -P 16 -DkLen 64 `
    -Expected 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'

# RFC 7914 §12 — vector #3: scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64)
Test-Vector -Label 'scrypt("pleaseletmein","SodiumChloride",N=16384,r=8,p=1,dkLen=64)' `
    -Password 'pleaseletmein' -Salt 'SodiumChloride' -N 16384 -R 8 -P 1 -DkLen 64 `
    -Expected '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'

if ($IncludeLargeVector) {
    # RFC 7914 §12 — vector #4: scrypt("pleaseletmein","SodiumChloride",1048576,8,1,64)
    # Requires ~1 GiB RAM.
    Test-Vector -Label 'scrypt("pleaseletmein","SodiumChloride",N=1048576,r=8,p=1,dkLen=64)' `
        -Password 'pleaseletmein' -Salt 'SodiumChloride' -N 1048576 -R 8 -P 1 -DkLen 64 `
        -Expected '2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4'
}
else {
    Write-Host '  SKIP            vector #4 (N=1048576, ~1 GiB) — pass -IncludeLargeVector to run' -ForegroundColor DarkGray
}

# Parameter validation: non-power-of-two N must throw
try {
    [void](Invoke-Scrypt -Password ([byte[]]@(1)) -Salt ([byte[]]@(1)) -N 1000 -R 1 -P 1 -DkLen 16)
    $fail++; Write-Host '  FAIL            rejects non-power-of-two CostFactor' -ForegroundColor Red
}
catch {
    $pass++; Write-Host '  PASS            rejects non-power-of-two CostFactor' -ForegroundColor Green
}

Write-Host ('=' * 52)
[string]$colour = if ($fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ("Results: $pass passed, $fail failed") -ForegroundColor $colour
if ($fail -gt 0) { exit 1 }
