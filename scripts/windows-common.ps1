# Shared deployment boundaries; no accounts or unrelated policy are modified.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BrokerService = 'ssh-brokerd'
$script:BrokerRoot = Join-Path $env:ProgramFiles 'ssh-credential-broker'
$script:BrokerWer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
function Assert-BrokerAdministrator {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Use native 64-bit Windows PowerShell 5.1 or PowerShell 7 on Windows.' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated administrator session is required.' }
}
function Assert-BrokerPlainPath([string] $Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point deployment path.' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }; $cursor = $parent
    }
}
function Invoke-BrokerSc([string[]] $Arguments) {
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Service management failed (sc.exe exit $LASTEXITCODE); no command output is included." }
}
function Set-BrokerDirectoryAcl([string] $Path, [string[]] $ReadSids = @(), [switch] $DenyWrite) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rights = if ($DenyWrite) { [Security.AccessControl.FileSystemRights]::ReadAndExecute } else { [Security.AccessControl.FileSystemRights]::FullControl }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, $inherit, 'None', 'Allow'))
    }
    foreach ($sid in $ReadSids) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'ReadAndExecute', $inherit, 'None', 'Allow')) }
    if ($DenyWrite) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Write', $inherit, 'None', 'Deny')) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-BrokerServiceRecord {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='ssh-brokerd'" -ErrorAction Stop
}
function Get-BrokerManagedState {
    Assert-BrokerPlainPath $script:BrokerRoot
    $path = Join-Path $script:BrokerRoot '.managed-install.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'No managed Windows installation record exists; nothing was removed.' }
    Assert-BrokerPlainPath $path
    $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($state.Version -ne 1 -or $state.Root -cne $script:BrokerRoot -or $state.Service -cne $script:BrokerService -or $state.Product -cne 'ssh-credential-broker-windows') { throw 'Installation ownership record is not recognized.' }
    foreach ($value in @($state.OperatorSid, $state.HarnessSid)) { $null = [Security.Principal.SecurityIdentifier]::new([string]$value) }
    $expected = '"' + (Join-Path $script:BrokerRoot 'ssh-brokerd.exe') + '" --operator-sid ' + $state.OperatorSid + ' --harness-sid ' + $state.HarnessSid
    if ($state.ImagePath -cne $expected) { throw 'Installation service command does not match the managed contract.' }
    $service = Get-BrokerServiceRecord
    if ($service -and ($service.PathName -cne $expected -or $service.StartName -ine 'NT SERVICE\ssh-brokerd')) { throw 'Existing service is not the managed broker service; nothing was removed.' }
    return $state
}
function Assert-BrokerUser([string] $Account) {
    if ([string]::IsNullOrWhiteSpace($Account)) { throw 'Specify an existing operator and harness user account.' }
    $sid = ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier])
    # SID translation alone also accepts groups; Win32_UserAccount must identify a real user.
    $user = Get-CimInstance -ClassName Win32_UserAccount -Filter ("SID='" + $sid.Value + "'") -ErrorAction Stop
    if (-not $user -or $user.Disabled) { throw 'The specified principal is not an enabled Windows user account.' }
    return $sid.Value
}
function Assert-BrokerHarness([string] $Sid) {
    if (-not ('BrokerWindowsNative' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'windows-native.cs') }
    $sids = [BrokerWindowsNative]::EffectiveSids($Sid)
    foreach ($group in $sids) {
        if ($group -match '^S-1-5-(18|19|20)$' -or $group -match '^S-1-5-80-' -or $group -match '^S-1-5-32-(544|547|548|549|550|551|552|556|557|569|573|575|576|577|578|580|582|583)$' -or $group -match '^S-1-5-21-(\d+-){3}(500|502|512|516|518|519|520|521|526|527)$') {
            throw 'Harness has a privileged effective SID (including nested or deny-only membership); use a dedicated unprivileged account.'
        }
    }
    $baseline = @('SeChangeNotifyPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeShutdownPrivilege', 'SeTimeZonePrivilege', 'SeUndockPrivilege')
    foreach ($right in [BrokerWindowsNative]::AccountRights($sids)) {
        if ($right.EndsWith('Privilege') -and $right -notin $baseline) { throw 'Harness has an elevated local-policy privilege; use a dedicated unprivileged account.' }
    }
}
function Get-BrokerServiceSid {
    # RtlCreateServiceSid: SHA-1 of the invariant uppercase UTF-16 service name.
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $digest = $sha.ComputeHash([Text.Encoding]::Unicode.GetBytes($script:BrokerService.ToUpperInvariant())) }
    finally { $sha.Dispose() }
    $parts = for ($offset = 0; $offset -lt 20; $offset += 4) { [BitConverter]::ToUInt32($digest, $offset) }
    return 'S-1-5-80-' + ($parts -join '-')
}
function Wait-BrokerServiceState([string] $State) {
    $controller = [ServiceProcess.ServiceController]::new($script:BrokerService)
    try { $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]$State, [timespan]::FromSeconds(30)) }
    finally { $controller.Dispose() }
}
