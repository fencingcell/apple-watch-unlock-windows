# AGPL-3.0-only. Build/test only; this script never installs a service.
[CmdletBinding()]
param([switch]$Release)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$profile = if ($Release) { @('--release') } else { @() }
Push-Location (Join-Path $repo 'backend')
try {
    & cargo test --locked -p watch-unlock-auth -p watch-login-probe
    if ($LASTEXITCODE -ne 0) { throw 'Probe tests failed' }
    & cargo build --locked -p watch-login-probe @profile
    if ($LASTEXITCODE -ne 0) { throw 'Probe build failed' }
    Write-Host 'Build complete. Installation, Watch authentication and cold-boot logon have not been validated by this build.'
} finally { Pop-Location }
