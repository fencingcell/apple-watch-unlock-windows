# AGPL-3.0-only. Fixtures only: never installs a service or changes system directories.
[CmdletBinding()]
param(
    [string]$FixtureParent = (Join-Path $PSScriptRoot '..\..\.git\sdd'),
    [switch]$RequirePrivilegedTests
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\Probe-DirectorySafety.ps1')
$root=Join-Path ([IO.Path]::GetFullPath($FixtureParent)) ('probe-directory-tests-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl="O:${sid}D:P(A;OICI;FA;;;${sid})(A;OICI;FA;;;SY)"
$failed=0
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $threw=$false
    try {& $Action} catch {$threw=$true}
    if (!$threw) {throw $Message}
}
function Test-Case([string]$Name,[scriptblock]$Body) {
    try {& $Body;Write-Output "PASS $Name"} catch {$script:failed++;Write-Output "FAIL ${Name}: $($_.Exception.Message)"}
}
try {
    Test-Case 'directory created during earlier absence is never adopted' {
        $path=Join-Path $root 'raced'
        if (Test-Path -LiteralPath $path) {throw 'Fixture must initially be absent'}
        [void][IO.Directory]::CreateDirectory($path)
        [IO.File]::WriteAllText((Join-Path $path 'probe-data-owned.txt'),'forged')
        $before=(Get-Acl -LiteralPath $path).Sddl
        Assert-Throws {New-ProbeDirectoryExclusive $path $sddl} 'Existing raced root was adopted'
        if ((Get-Acl -LiteralPath $path).Sddl -ne $before) {throw 'Rejected root ACL was changed'}
        if ([IO.File]::ReadAllText((Join-Path $path 'probe-data-owned.txt')) -ne 'forged') {throw 'Rejected root contents were changed'}
    }
    Test-Case 'new directory starts with protected supplied owner and ACL' {
        $path=Join-Path $root 'protected'
        New-ProbeDirectoryExclusive $path $sddl
        $acl=Get-Acl -LiteralPath $path
        if (!$acl.AreAccessRulesProtected) {throw 'Creation inherited parent ACL before protection'}
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {throw 'Creation owner mismatch'}
        if (@($acl.Access | Where-Object IsInherited).Count) {throw 'Creation inherited an ACE'}
    }
    Test-Case 'directory pin prevents rename during confirmation' {
        $path=Join-Path $root 'pinned';$moved=Join-Path $root 'moved'
        New-ProbeDirectoryExclusive $path $sddl
        $pin=Open-ProbePinnedDirectory $path
        try {Assert-Throws {[IO.Directory]::Move($path,$moved)} 'Pinned directory could be replaced'} finally {if ($pin) {$pin.Dispose()}}
        [IO.Directory]::Move($path,$moved)
    }
    Test-Case 'junction appearing instead of a missing root is rejected without target writes' {
        $target=Join-Path $root 'junction-target';$link=Join-Path $root 'junction'
        [void][IO.Directory]::CreateDirectory($target)
        [void](New-Item -ItemType Junction -Path $link -Target $target)
        try {
            Assert-Throws {New-ProbeDirectoryExclusive $link $sddl} 'Raced junction was adopted'
            Assert-Throws {$pin=Open-ProbePinnedDirectory $link;if($pin){$pin.Dispose()}} 'Junction was followed by pin'
            if (@(Get-ChildItem -LiteralPath $target -Force).Count) {throw 'Junction target modified'}
        } finally {[IO.Directory]::Delete($link,$false)}
    }
    Test-Case 'ancestor pins prevent parent replacement while creating a child' {
        $parent=Join-Path $root 'ancestor';$moved=Join-Path $root 'ancestor-moved'
        New-ProbeDirectoryExclusive $parent $sddl
        $pins=[Collections.Generic.List[IDisposable]]::new()
        try {
            Add-ProbeAncestorPins (Join-Path $parent 'child') $pins
            Assert-Throws {[IO.Directory]::Move($parent,$moved)} 'Pinned ancestor could be replaced'
        } finally {for($i=$pins.Count-1;$i -ge 0;$i--){$pins[$i].Dispose()}}
    }
    Test-Case 'SYSTEM-only child requires administrator backup privilege and keeps its ACL' {
        $path=Join-Path $root 'system-child';$moved=Join-Path $root 'system-child-moved'
        New-ProbeDirectoryExclusive $path "O:${sid}D:P(A;OICI;FA;;;SY)"
        # Fixture owner remains this user solely so its original ACL can be inspected.
        # No child READ_DATA permission exists. Production uses an elevated admin token.
        $before=(Get-Acl -LiteralPath $path).Sddl
        $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        try {
            if($admin) {
                $pin=Open-ProbePinnedDirectory $path -BackupAccess
                try {Assert-Throws {[IO.Directory]::Move($path,$moved)} 'SYSTEM-only child could be replaced'} finally {$pin.Dispose()}
            } else {
                Assert-Throws {$pin=Open-ProbePinnedDirectory $path -BackupAccess;if($pin){$pin.Dispose()}} 'Non-admin token opened SYSTEM-only child'
                if($RequirePrivilegedTests){throw 'An elevated administrator token is required for positive SYSTEM-only pin verification'}
                Write-Output 'SKIP positive SYSTEM-only pin: elevated administrator token required (non-admin fail-closed verified)'
            }
            if((Get-Acl -LiteralPath $path).Sddl -ne $before){throw 'Pin weakened private child ACL'}
        } finally {
            # icacls changes only this fixture DACL; Set-Acl requests additional
            # privileges for otherwise unreadable directories on some PS runtimes.
            & "$env:SystemRoot/System32/icacls.exe" $path '/grant:r' "*${sid}:(OI)(CI)F" | Out-Null
            if($LASTEXITCODE -ne 0){throw 'Could not restore disposable fixture ACL'}
        }
    }
    Test-Case 'preexisting file never becomes a directory' {
        $path=Join-Path $root 'occupied-file';[IO.File]::WriteAllText($path,'unchanged')
        try {
            Assert-Throws {New-ProbeDirectoryExclusive $path $sddl} 'Existing file adopted'
            Assert-Throws {$pin=Open-ProbePinnedDirectory $path;if($pin){$pin.Dispose()}} 'File accepted as directory'
            if([IO.File]::ReadAllText($path) -ne 'unchanged'){throw 'Existing file altered'}
        } finally {[IO.File]::Delete($path)}
    }
} finally {
    # Every target is an exact fixture child; junction removed separately, no recursive delete.
    foreach($name in @('raced','protected','pinned','moved','junction-target','ancestor','ancestor-moved','system-child','system-child-moved')) {
        $path=Join-Path $root $name
        if(Test-Path -LiteralPath $path) {
            $marker=Join-Path $path 'probe-data-owned.txt'
            if(Test-Path -LiteralPath $marker){[IO.File]::Delete($marker)}
            [IO.Directory]::Delete($path,$false)
        }
    }
    [IO.Directory]::Delete($root,$false)
}
if($failed){throw "$failed directory safety tests failed"}
