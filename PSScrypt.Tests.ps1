#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 test suite for the PSScrypt module, built on the official
    RFC 7914 §12 scrypt test vectors.

.DESCRIPTION
    Verifies Invoke-Scrypt produces the exact derived keys published in
    RFC 7914 (https://www.rfc-editor.org/rfc/rfc7914#section-12). These vectors
    are the canonical correctness check for any scrypt implementation and are
    independent of the Spectre/PowerPass layer that consumes this module.

    Vector #4 (N=1048576) needs ~1 GiB of RAM and takes a while; it is skipped
    unless the environment variable PSSCRYPT_LARGE_VECTOR is set.

.EXAMPLE
    Invoke-Pester -Path ./PSScrypt.Tests.ps1 -Output Detailed

.EXAMPLE
    $env:PSSCRYPT_LARGE_VECTOR = 1
    Invoke-Pester -Path ./PSScrypt.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    $script:Vectors = @(
        @{
            Name = 'RFC 7914 #1'; Password = ''; Salt = ''; N = 16; R = 1; P = 1; DkLen = 64
            Expected = '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906'
        }
        @{
            Name = 'RFC 7914 #2'; Password = 'password'; Salt = 'NaCl'; N = 1024; R = 8; P = 16; DkLen = 64
            Expected = 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'
        }
        @{
            Name = 'RFC 7914 #3'; Password = 'pleaseletmein'; Salt = 'SodiumChloride'; N = 16384; R = 8; P = 1; DkLen = 64
            Expected = '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'
        }
    )
    # Vector #4 needs ~1 GiB RAM.
    $script:LargeVector = @{
        Name = 'RFC 7914 #4'; Password = 'pleaseletmein'; Salt = 'SodiumChloride'; N = 1048576; R = 8; P = 1; DkLen = 64
        Expected = '2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4'
    }
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'PSScrypt.psm1') -Force

    function Get-ScryptHex {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
            Justification = 'Public RFC 7914 test vectors, not secrets.')]
        param([string]$Password, [string]$Salt, [int]$N, [int]$R, [int]$P, [int]$DkLen)
        [byte[]]$key = Invoke-Scrypt -Password ([Text.Encoding]::ASCII.GetBytes($Password)) `
            -Salt ([Text.Encoding]::ASCII.GetBytes($Salt)) -N $N -R $R -P $P -DkLen $DkLen
        ([BitConverter]::ToString($key) -replace '-').ToLower()
    }
}

Describe 'Invoke-Scrypt' {

    Context 'RFC 7914 §12 test vectors' {
        It 'matches <Name> (N=<N>, r=<R>, p=<P>, dkLen=<DkLen>)' -ForEach $script:Vectors {
            Get-ScryptHex -Password $Password -Salt $Salt -N $N -R $R -P $P -DkLen $DkLen |
                Should -BeExactly $Expected
        }

        It 'matches <Name> (N=<N>, ~1 GiB RAM)' -Tag 'Large' -Skip:(-not $env:PSSCRYPT_LARGE_VECTOR) -ForEach @($script:LargeVector) {
            Get-ScryptHex -Password $Password -Salt $Salt -N $N -R $R -P $P -DkLen $DkLen |
                Should -BeExactly $Expected
        }
    }

    Context 'Parameter validation' {
        BeforeAll {
            $script:one = [byte[]]@(1)
        }

        It 'rejects a non-power-of-two CostFactor' {
            { Invoke-Scrypt -Password $script:one -Salt $script:one -N 1000 -R 1 -P 1 -DkLen 16 } |
                Should -Throw
        }

        It 'rejects oversized r=<R> p=<P> with an ArgumentException' -ForEach @(
            @{ R = 16777216; P = 1 }
            @{ R = 8; P = 2097152 }
            @{ R = 1073741824; P = 1 }
        ) {
            $err = $null
            try { [void](Invoke-Scrypt -Password $script:one -Salt $script:one -N 16 -R $R -P $P -DkLen 16) }
            catch { $err = $_.Exception.InnerException ?? $_.Exception }
            $err | Should -BeOfType [ArgumentException]
        }
    }

    Context 'Return type' {
        It 'returns [byte[]] of length <Len> without a caller-side cast' -ForEach @(
            @{ Len = 1 }
            @{ Len = 32 }
        ) {
            $k = Invoke-Scrypt -Password ([byte[]]@(1)) -Salt ([byte[]]@(1)) -N 16 -R 1 -P 1 -DkLen $Len
            Should -ActualValue $k -BeOfType [byte[]]
            $k.Length | Should -Be $Len
        }
    }
}
