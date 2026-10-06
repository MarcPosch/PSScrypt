# PSScrypt

PSScrypt — a self-contained implementation of [scrypt (RFC 7914)](https://www.rfc-editor.org/rfc/rfc7914) for PowerShell 7.

PowerShell 7 ships no native scrypt and the .NET base class library does not expose one, so the memory-hard core is implemented in C# compiled at module load time via `Add-Type`. It uses only types from the .NET BCL (`System.Security.Cryptography` for HMAC-SHA-256), so it compiles and runs identically on Windows, Linux and macOS, with no external dependencies.

The module is generic: it can derive a key from any password and salt with any valid scrypt parameters. It was written for use by PowerPass (Spectre algorithm) but is deliberately self-contained.

## Requirements

- PowerShell 7.0 or later (`Core` edition)

## Installation

Copy the module folder somewhere on your `$env:PSModulePath`, or import it by path:

```powershell
Import-Module ./PSScrypt.psd1
```

## Usage

`Invoke-Scrypt` takes a password and salt as byte arrays and returns the derived key as a `[byte[]]`.

| Parameter           | Alias    | Description                                                       |
|---------------------|----------|-------------------------------------------------------------------|
| `-Password`         |          | Secret as `byte[]`. May be empty.                                 |
| `-Salt`             |          | Salt as `byte[]`. May be empty.                                   |
| `-CostFactor`       | `-N`     | CPU/memory cost. Must be a power of two greater than 1.           |
| `-BlockSize`        | `-R`     | Block size `r` (>= 1).                                            |
| `-Parallelization`  | `-P`     | Parallelization `p` (>= 1).                                       |
| `-DerivedKeyLength` | `-DkLen` | Output length in bytes (>= 1).                                    |

`p * r` must be less than 2^30 (RFC 7914), and `p * 128 * r` bytes must fit in a single .NET array. Invalid parameters throw an `ArgumentException`.

scrypt is memory-hard by design. Memory use is roughly `128 * N * r` bytes per parallel lane, so `N=32768, r=8` uses about 32 MiB and takes a moment.

## Examples

Derive a 32-byte key with commonly used interactive-login parameters:

```powershell
$pw   = [Text.Encoding]::UTF8.GetBytes('correct horse battery staple')
$salt = [Text.Encoding]::UTF8.GetBytes('seasalt')

$key = Invoke-Scrypt -Password $pw -Salt $salt -N 32768 -R 8 -P 1 -DkLen 32
```

Show the key as a hex string:

```powershell
[Convert]::ToHexString($key).ToLower()
```

Use the full parameter names instead of the aliases:

```powershell
Invoke-Scrypt -Password $pw -Salt $salt `
              -CostFactor 16384 -BlockSize 8 -Parallelization 1 -DerivedKeyLength 64
```

Use a random salt and keep it alongside the derived key, for example to hash a password for storage:

```powershell
$salt = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
$key  = Invoke-Scrypt -Password $pw -Salt $salt -N 32768 -R 8 -P 1 -DkLen 32

$stored = '{0}:{1}' -f [Convert]::ToBase64String($salt), [Convert]::ToBase64String($key)
```

Verify a password against a stored value:

```powershell
$saltB64, $keyB64 = $stored -split ':'
$expected = [Convert]::FromBase64String($keyB64)
$actual   = Invoke-Scrypt -Password $pw -Salt ([Convert]::FromBase64String($saltB64)) `
                          -N 32768 -R 8 -P 1 -DkLen $expected.Length

[Security.Cryptography.CryptographicOperations]::FixedTimeEquals($actual, $expected)
```

RFC 7914 §12 test vector #1:

```powershell
$key = Invoke-Scrypt -Password ([byte[]]@()) -Salt ([byte[]]@()) `
                     -N 16 -R 1 -P 1 -DkLen 64
[Convert]::ToHexString($key).ToLower()
# 77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906
```

## Tests

The test suite checks the module against the official RFC 7914 §12 test vectors, return type and parameter validation:

```powershell
pwsh -File ./PSScrypt.Tests.ps1

# also run vector #4 (N=1048576, needs ~1 GiB RAM)
pwsh -File ./PSScrypt.Tests.ps1 -IncludeLargeVector
```

## License

See [LICENSE](LICENSE).

## Idea and Credits

I needed a powershell-only implementation of scrypt without external dependencies.
Since I did not find any, I decided to create one.

Credit, where credit is due:
Without AI, this would not have been possible in a reasonable timeframe using my spare time only.
