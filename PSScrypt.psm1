#Requires -Version 7.0
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

<#
    PSScrypt — a self-contained implementation of scrypt (RFC 7914)

    PowerShell 7 ships no native scrypt and the .NET base class library does
    not expose one, so the memory-hard core is implemented here in self-contained
    C# compiled at module load time via Add-Type. It uses only types from the
    .NET BCL (System.Security.Cryptography for HMAC-SHA-256), so it compiles and
    runs identically on Windows, Linux and macOS under PowerShell 7.

    This module is consumed by PowerPass (Spectre algorithm) but is deliberately
    self-contained and generic: it can derive a key from any password/salt with
    any valid scrypt parameters.

    Public surface:
        Invoke-Scrypt -Password <byte[]> -Salt <byte[]> -CostFactor <int>
                      -BlockSize <int> -Parallelization <int>
                      -DerivedKeyLength <int>   ->  [byte[]]
#>

# ---------------------------------------------------------------------------
# Inline C# — scrypt core (RFC 7914): PBKDF2-SHA-256, Salsa20/8, BlockMix, ROMix.
# Add-Type compiles once per process; the guard avoids duplicate-type errors on
# re-import with -Force.
# ---------------------------------------------------------------------------
$script:PSScryptCSharp = @'
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

public static class PSScryptCore {

    /// <summary>
    /// scrypt key derivation (RFC 7914).
    /// N must be a power of two greater than 1; r, p, dkLen must be positive.
    /// </summary>
    public static byte[] Scrypt(byte[] password, byte[] salt, int N, int r, int p, int dkLen) {
        if (password == null) throw new ArgumentNullException("password");
        if (salt == null) throw new ArgumentNullException("salt");
        if (N <= 1 || (N & (N - 1)) != 0)
            throw new ArgumentException("N must be a power of two greater than 1.", "N");
        if (r < 1) throw new ArgumentOutOfRangeException("r", "r must be >= 1.");
        if (p < 1) throw new ArgumentOutOfRangeException("p", "p must be >= 1.");
        if (dkLen < 1) throw new ArgumentOutOfRangeException("dkLen", "dkLen must be >= 1.");
        // RFC 7914: p * r < 2^30. The p * 128 * r byte working array must also
        // fit in a single .NET array (just under 2 GiB).
        if ((long)p * r >= (1L << 30))
            throw new ArgumentException("p * r must be less than 2^30.");
        if ((long)p * r * 128 > 0x7FFFFFC7L)
            throw new ArgumentException("p * r is too large: p * 128 * r bytes exceeds the maximum array size.");

        int blockSize = 128 * r;
        byte[] B = PBKDF2_SHA256(password, salt, 1, p * blockSize);
        for (int i = 0; i < p; i++) {
            byte[] block = new byte[blockSize];
            Buffer.BlockCopy(B, i * blockSize, block, 0, blockSize);
            ROMix(block, r, N);
            Buffer.BlockCopy(block, 0, B, i * blockSize, blockSize);
            Array.Clear(block, 0, block.Length);
        }
        byte[] result = PBKDF2_SHA256(password, B, 1, dkLen);
        Array.Clear(B, 0, B.Length);
        return result;
    }

    // -----------------------------------------------------------------------
    // PBKDF2-SHA-256 (RFC 2898)
    // -----------------------------------------------------------------------
    private static byte[] PBKDF2_SHA256(byte[] password, byte[] salt, int iterations, int dkLen) {
        const int hashLen = 32; // SHA-256 output bytes
        int numBlocks = (int)(((long)dkLen + hashLen - 1) / hashLen);
        byte[] result = new byte[dkLen];
        using var prf = new HMACSHA256(password);
        for (int blockNum = 1; blockNum <= numBlocks; blockNum++) {
            // U1 = PRF(Password, Salt || INT(blockNum))
            byte[] saltBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);
            saltBlock[salt.Length]     = (byte)((blockNum >> 24) & 0xff);
            saltBlock[salt.Length + 1] = (byte)((blockNum >> 16) & 0xff);
            saltBlock[salt.Length + 2] = (byte)((blockNum >>  8) & 0xff);
            saltBlock[salt.Length + 3] = (byte)( blockNum        & 0xff);
            byte[] U = prf.ComputeHash(saltBlock);
            byte[] T = (byte[])U.Clone();
            for (int iter = 1; iter < iterations; iter++) {
                U = prf.ComputeHash(U);
                for (int j = 0; j < hashLen; j++) T[j] ^= U[j];
            }
            int offset  = (int)((long)(blockNum - 1) * hashLen);
            int copyLen = Math.Min(hashLen, dkLen - offset);
            Buffer.BlockCopy(T, 0, result, offset, copyLen);
            Array.Clear(saltBlock, 0, saltBlock.Length);
            Array.Clear(U, 0, U.Length);
            Array.Clear(T, 0, T.Length);
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Salsa20/8 core, via Bernstein's quarter/row/column-round decomposition
    // (RFC 7914 §3 / the Salsa20 specification). This explicit form is far less
    // error-prone than a hand-inlined round variant.
    // -----------------------------------------------------------------------
    private static uint R(uint a, int b) => (a << b) | (a >> (32 - b));

    // Salsa quarter-round on state indices (a,b,c,d) interpreted as (y0,y1,y2,y3).
    private static void QR(uint[] x, int a, int b, int c, int d) {
        x[b] ^= R(x[a] + x[d],  7);
        x[c] ^= R(x[b] + x[a],  9);
        x[d] ^= R(x[c] + x[b], 13);
        x[a] ^= R(x[d] + x[c], 18);
    }

    private static void Salsa20_8(uint[] B) {
        uint[] x = new uint[16];
        Buffer.BlockCopy(B, 0, x, 0, 64);
        for (int i = 0; i < 4; i++) {          // 4 double-rounds = 8 rounds
            // column rounds
            QR(x,  0,  4,  8, 12);
            QR(x,  5,  9, 13,  1);
            QR(x, 10, 14,  2,  6);
            QR(x, 15,  3,  7, 11);
            // row rounds
            QR(x,  0,  1,  2,  3);
            QR(x,  5,  6,  7,  4);
            QR(x, 10, 11,  8,  9);
            QR(x, 15, 12, 13, 14);
        }
        for (int i = 0; i < 16; i++) B[i] += x[i];
        Array.Clear(x, 0, x.Length);
    }

    // -----------------------------------------------------------------------
    // BlockMix — operates on 2r blocks of 64 bytes (stored as uint[2r*16])
    // -----------------------------------------------------------------------
    private static void BlockMix(uint[] B, int r) {
        int blockCount = 2 * r;
        uint[] X = new uint[16];
        uint[] Y = new uint[blockCount * 16];
        // X = last block of B
        Buffer.BlockCopy(B, (blockCount - 1) * 64, X, 0, 64);
        for (int i = 0; i < blockCount; i++) {
            for (int j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
            Salsa20_8(X);
            Buffer.BlockCopy(X, 0, Y, i * 64, 64);
        }
        // Reorder: even-indexed blocks first, then odd-indexed
        for (int i = 0; i < r; i++) {
            Buffer.BlockCopy(Y,  (2 * i)      * 64, B,  i      * 64, 64);
            Buffer.BlockCopy(Y, ((2 * i) + 1) * 64, B, (i + r) * 64, 64);
        }
        Array.Clear(X, 0, X.Length);
        Array.Clear(Y, 0, Y.Length);
    }

    // -----------------------------------------------------------------------
    // ROMix — sequential memory-hard function (RFC 7914 §3)
    // -----------------------------------------------------------------------
    private static void ROMix(byte[] block, int r, int N) {
        int wordCount = 32 * r; // number of uint32 words in one block
        uint[] X = new uint[wordCount];
        // Decode little-endian bytes to uint[]
        for (int i = 0; i < wordCount; i++)
            X[i] = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(block, i * 4, 4));
        // Fill lookup table V
        uint[][] V = new uint[N][];
        for (int i = 0; i < N; i++) {
            V[i] = (uint[])X.Clone();
            BlockMix(X, r);
        }
        // Mix phase: Integerify selects which V entry to XOR in (N is a power of 2)
        for (int i = 0; i < N; i++) {
            int j = (int)(X[(2 * r - 1) * 16] & (uint)(N - 1));
            for (int k = 0; k < wordCount; k++) X[k] ^= V[j][k];
            BlockMix(X, r);
        }
        // Encode back to little-endian bytes
        for (int i = 0; i < wordCount; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(block, i * 4, 4), X[i]);
        Array.Clear(X, 0, X.Length);
        for (int i = 0; i < N; i++) Array.Clear(V[i], 0, V[i].Length);
    }
}
'@

if (-not ('PSScryptCore' -as [type])) {
    Add-Type -TypeDefinition $script:PSScryptCSharp -Language CSharp
}

<#
.SYNOPSIS
    Derives a key from a password and salt using scrypt (RFC 7914).

.DESCRIPTION
    A pure-PowerShell scrypt implementation with no external dependencies. The
    memory-hard core is compiled from inline C# at module load and runs on
    Windows, Linux and macOS under PowerShell 7.

    scrypt is intentionally CPU- and memory-hard. Memory use is approximately
    128 * CostFactor * BlockSize bytes (e.g. CostFactor=32768, BlockSize=8 uses
    about 32 MiB per parallel lane and takes a couple of seconds — by design).

.PARAMETER Password
    The password/secret as a byte array. May be empty.

.PARAMETER Salt
    The salt as a byte array. May be empty.

.PARAMETER CostFactor
    The CPU/memory cost parameter N. Must be a power of two greater than 1.
    Alias: -N.

.PARAMETER BlockSize
    The block size parameter r (must be >= 1). Alias: -R.

.PARAMETER Parallelization
    The parallelization parameter p (must be >= 1). Alias: -P.

.PARAMETER DerivedKeyLength
    The desired output length in bytes (must be >= 1). Alias: -DkLen.

.OUTPUTS
    [byte[]] — the derived key of length DerivedKeyLength.

.EXAMPLE
    # RFC 7914 §12 test vector #1
    $key = Invoke-Scrypt -Password ([byte[]]@()) -Salt ([byte[]]@()) `
                         -CostFactor 16 -BlockSize 1 -Parallelization 1 -DerivedKeyLength 64
    [BitConverter]::ToString($key) -replace '-'

.EXAMPLE
    $pw   = [Text.Encoding]::UTF8.GetBytes('correct horse battery staple')
    $salt = [Text.Encoding]::UTF8.GetBytes('seasalt')
    Invoke-Scrypt -Password $pw -Salt $salt -N 32768 -R 8 -P 1 -DkLen 32

.NOTES
    Parameter names follow the descriptive convention; the single-letter scrypt
    names (N, r, p, dkLen) are available as aliases.
#>
function Invoke-Scrypt {
    [CmdletBinding()]
    [OutputType([byte[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '',
        Justification = 'The unary comma in the return statement keeps the byte[] from being unrolled; the output is a byte[].')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'scrypt operates on a raw byte[] secret by design; there is no SecureString form for a KDF input.')]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Password,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Salt,

        [Parameter(Mandatory)]
        [Alias('N')]
        [int]$CostFactor,

        [Parameter(Mandatory)]
        [Alias('R')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$BlockSize,

        [Parameter(Mandatory)]
        [Alias('P')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Parallelization,

        [Parameter(Mandatory)]
        [Alias('DkLen')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DerivedKeyLength
    )

    # N must be a power of two greater than 1.
    if ($CostFactor -le 1 -or ($CostFactor -band ($CostFactor - 1)) -ne 0) {
        throw [System.ArgumentException]::new(
            "CostFactor (N) must be a power of two greater than 1; got $CostFactor.", 'CostFactor')
    }

    # Unary comma stops PowerShell unrolling the array into the pipeline (and
    # collapsing a 1-byte result into a bare [byte]).
    return ,[PSScryptCore]::Scrypt($Password, $Salt, $CostFactor, $BlockSize, $Parallelization, $DerivedKeyLength)
}

Export-ModuleMember -Function 'Invoke-Scrypt'
