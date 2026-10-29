#Requires -RunAsAdministrator
# AGPL-3.0-only. Retains ProgramData identity/trust for deliberate administrator handling.
[CmdletBinding()]
param([string]$InstallDirectory = (Join-Path $env:ProgramFiles 'WatchLoginProbe'))
$ErrorActionPreference = 'Stop'
function Assert-NoReparse([string]$Path) {
    $next = [IO.Path]::GetFullPath($Path)
    while ($next) {
        if ((Test-Path -LiteralPath $next) -and ((Get-Item -LiteralPath $next -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Reparse path refused: $next" }
        $parentInfo = [IO.Directory]::GetParent($next)
        $parent = if ($parentInfo) { $parentInfo.FullName } else { $null }
        if ($parent -eq $next) { break }
        $next = $parent
    }
}
$install = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'WatchLoginProbe')).TrimEnd('\')
if ($install -ne $expected) { throw 'Only the dedicated Program Files\WatchLoginProbe directory can be removed' }
$exe = Join-Path $install 'watch-login-probe.exe'
$marker = Join-Path $install 'probe-service-owned.txt'
foreach ($path in @($install,$exe,$marker)) { Assert-NoReparse $path }
if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or [IO.File]::ReadAllText($marker) -ne 'WatchLoginProbe-v1') { throw 'Owned installation marker missing' }
$existing = Get-CimInstance Win32_Service -Filter "Name='WatchLoginProbe'"
if ($existing) {
    if ($existing.PathName -ne ('"' + $exe + '" service') -or $existing.StartName -ne 'LocalSystem') { throw 'Refusing to remove unexpected service' }
    Stop-Service -Name WatchLoginProbe
    (Get-Service -Name WatchLoginProbe).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    & "$env:SystemRoot/System32/sc.exe" delete WatchLoginProbe | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SCM service deletion failed' }
}
foreach ($path in @($exe,$marker)) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } }
# No recursive deletion: unknown files are retained.
if (@(Get-ChildItem -LiteralPath $install -Force).Count -eq 0) { [IO.Directory]::Delete($install,$false) }
Write-Host 'Probe service removed. ProgramData\WatchLoginProbe identity and enrollment retained; no Credential Provider or autologon settings were changed.'
