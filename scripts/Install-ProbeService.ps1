#Requires -RunAsAdministrator
# AGPL-3.0-only. Explicit administrative installation, never invoked by builds.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'WatchLoginProbe'),
    [string]$WatchPublicKeyFile,
    [switch]$Start
)
$ErrorActionPreference = 'Stop'
$serviceName = 'WatchLoginProbe'
function Assert-NoReparse([string]$Path) {
    $next = [IO.Path]::GetFullPath($Path)
    while ($next) {
        if (Test-Path -LiteralPath $next) {
            $item = Get-Item -LiteralPath $next -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse path refused: $next" }
        }
        $parentInfo = [IO.Directory]::GetParent($next)
        $parent = if ($parentInfo) { $parentInfo.FullName } else { $null }
        if ($parent -eq $next) { break }
        $next = $parent
    }
}
function Invoke-Icacls([string[]]$Arguments) {
    & "$env:SystemRoot/System32/icacls.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'ACL operation failed' }
}
function Invoke-Sc([string[]]$Arguments) {
    & "$env:SystemRoot/System32/sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service configuration failed' }
}
function Set-ProtectedAcl([string]$Path,[string[]]$Rules) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $inherit = if ((Get-Item -LiteralPath $Path).PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($rule in $Rules) {
        $sid,$rights = $rule.Split(':',2)
        $entry = [Security.AccessControl.FileSystemAccessRule]::new(([Security.Principal.SecurityIdentifier]$sid),([Security.AccessControl.FileSystemRights]$rights),$inherit,([Security.AccessControl.PropagationFlags]::None),([Security.AccessControl.AccessControlType]::Allow))
        $acl.AddAccessRule($entry)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-TrustedDirectory([string]$Path) {
    Assert-NoReparse $Path
    if (!(Test-Path -LiteralPath $Path)) { return }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw "Untrusted directory owner: $Path" }
    $write = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and $sid -notin @('S-1-5-18','S-1-5-32-544')) { throw "Untrusted writable directory: $Path" }
    }
}
$install = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'WatchLoginProbe')).TrimEnd('\')
if ($install -ne $expected) { throw 'InstallDirectory must be the dedicated Program Files\WatchLoginProbe directory' }
$data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'WatchLoginProbe'))
$secrets = Join-Path $data 'secrets'
$public = Join-Path $data 'public'
$dataMarker = Join-Path $data 'probe-data-owned.txt'
$source = [IO.Path]::GetFullPath($Executable)
foreach ($path in @($install,$data,$secrets,$public,$source)) { Assert-NoReparse $path }
# Markers alone never establish ownership: a normal user can forge marker contents.
foreach ($path in @($install,$data,$public)) { Assert-TrustedDirectory $path }
if (!(Test-Path -LiteralPath $source -PathType Leaf) -or [IO.Path]::GetExtension($source) -ne '.exe') { throw 'Executable must be an existing EXE' }
$destination = Join-Path $install 'watch-login-probe.exe'
if ($source -eq $destination) { throw 'Supply a built EXE outside the install directory' }
$binaryPath = '"' + $destination + '" service'
$existing = Get-CimInstance Win32_Service -Filter "Name='WatchLoginProbe'"
if ($existing -and ($existing.PathName -ne $binaryPath -or $existing.StartName -ne 'LocalSystem')) { throw 'Existing service is not this owned LocalSystem probe' }
$watchHex = $null
if ($WatchPublicKeyFile) {
    $watchPath = [IO.Path]::GetFullPath($WatchPublicKeyFile); Assert-NoReparse $watchPath
    if ((Get-Item -LiteralPath $watchPath).Length -gt 132) { throw 'Public key file is too large' }
    $watchHex = [IO.File]::ReadAllText($watchPath).TrimEnd("`r","`n")
    if ($watchHex -cnotmatch '^04[0-9a-f]{128}$') { throw 'Expected a lowercase X9.63 P-256 public key' }
    $bytes = New-Object byte[] 65
    for ($i=0; $i -lt 65; $i++) { $bytes[$i] = [Convert]::ToByte($watchHex.Substring(2*$i,2),16) }
    # BCRYPT_ECCPUBLIC_BLOB: ECDSA P-256 magic + 32-byte coordinate width + X/Y.
    $blob = [byte[]](@(0x45,0x43,0x53,0x31,0x20,0,0,0) + $bytes[1..64])
    $key = [Security.Cryptography.CngKey]::Import($blob,[Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    $key.Dispose()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    Write-Host "Compare the Watch key fingerprint with the Watch/iPhone display: $fingerprint"
    if ((Read-Host 'Type the complete matching fingerprint to enroll for the SYSTEM service') -cne $fingerprint) { throw 'Fingerprint not confirmed' }
}
# Existing directories must carry our marker; never claim another application's files.
$marker = Join-Path $install 'probe-service-owned.txt'
if (Test-Path -LiteralPath $install) {
    Assert-NoReparse $marker
    if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or [IO.File]::ReadAllText($marker) -ne 'WatchLoginProbe-v1') { throw 'Unrecognized install directory' }
}
if (Test-Path -LiteralPath $data) {
    Assert-NoReparse $dataMarker
    if (!(Test-Path -LiteralPath $dataMarker -PathType Leaf) -or [IO.File]::ReadAllText($dataMarker) -ne 'WatchLoginProbe-data-v1') { throw 'Unrecognized service data directory' }
}
if ($existing) { Stop-Service -Name $serviceName; (Get-Service -Name $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
foreach ($path in @($install,$data)) {
    if (!(Test-Path -LiteralPath $path)) {
        [void][IO.Directory]::CreateDirectory($path)
        Set-ProtectedAcl $path @('S-1-5-18:FullControl','S-1-5-32-544:FullControl','S-1-5-32-545:ReadAndExecute')
        Invoke-Icacls @($path,'/setowner','*S-1-5-32-544')
        if (@(Get-ChildItem -LiteralPath $path -Force).Count -ne 0) { throw 'New application root was unexpectedly populated' }
    }
}
# Protected parent roots prevent ordinary users from creating/replacing children.
foreach ($path in @($secrets,$public)) { if (!(Test-Path -LiteralPath $path)) { [void][IO.Directory]::CreateDirectory($path) } }
# Validate owned descendants before ACL/copy operations.
foreach ($path in @($destination,$marker,(Join-Path $public 'computer-public-key.txt'))) { Assert-NoReparse $path }
Set-ProtectedAcl $install @('S-1-5-18:FullControl','S-1-5-32-544:FullControl','S-1-5-32-545:ReadAndExecute')
Set-ProtectedAcl $data @('S-1-5-18:FullControl','S-1-5-32-544:FullControl','S-1-5-32-545:ReadAndExecute')
Set-ProtectedAcl $public @('S-1-5-18:FullControl','S-1-5-32-544:FullControl','S-1-5-32-545:ReadAndExecute')
foreach ($path in @($install,$data,$public)) { Invoke-Icacls @($path,'/setowner','*S-1-5-32-544') }
[IO.File]::WriteAllText($dataMarker,'WatchLoginProbe-data-v1',[Text.Encoding]::ASCII)
# An administrator may take ownership for enrollment; runtime ACL is restored in finally.
Invoke-Icacls @($secrets,'/setowner','*S-1-5-32-544')
try {
    Set-ProtectedAcl $secrets @('S-1-5-18:FullControl','S-1-5-32-544:FullControl')
    # Directory enumeration supplies attributes without opening SYSTEM-only child files.
    # Do not Get-Item, read, decrypt or change the ACL of computer.dpapi.
    $children = @(Get-ChildItem -LiteralPath $secrets -Force)
    foreach ($child in $children) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse child in secrets directory refused' }
        if ($child.PSIsContainer) { throw 'Unexpected subdirectory in secrets directory' }
    }
    if ($watchHex) {
        $trust = Join-Path $secrets 'watch-public-key.txt'
        # Parent FullControl includes DELETE_CHILD; no child ACL weakening is necessary.
        if ($children.Name -contains 'watch-public-key.txt') { [IO.File]::Delete($trust) }
        [IO.File]::WriteAllText($trust,$watchHex,[Text.Encoding]::ASCII)
        Set-ProtectedAcl $trust @('S-1-5-18:FullControl')
        Invoke-Icacls @($trust,'/setowner','*S-1-5-18')
    }
} finally {
    Set-ProtectedAcl $secrets @('S-1-5-18:FullControl')
    Invoke-Icacls @($secrets,'/setowner','*S-1-5-18')
}
Copy-Item -LiteralPath $source -Destination $destination -Force
[IO.File]::WriteAllText($marker,'WatchLoginProbe-v1',[Text.Encoding]::ASCII)
if (!$existing) { New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'Watch Login Authentication Probe' -StartupType Automatic | Out-Null }
Invoke-Sc @('config',$serviceName,'start=','auto','obj=','LocalSystem')
Invoke-Sc @('sidtype',$serviceName,'unrestricted')
Invoke-Sc @('description',$serviceName,'Signed Watch authentication probe only. Does not submit a Windows logon.')
Write-Host 'Installed automatic SYSTEM probe. Service identity is separate from foreground identity; pair its computer fingerprint explicitly on the Watch.'
Write-Host 'After first service start: watch-login-probe show-identity --service-data. Diagnostics: ProgramData\WatchLoginProbe\public\service-events.log (bounded 64 KiB, UTC milliseconds and actual process session). Enroll/update only public Watch key with this script; no user DPAPI blob is copied.'
if ($Start) { Start-Service -Name $serviceName }
