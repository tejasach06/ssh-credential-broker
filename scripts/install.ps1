<#
.SYNOPSIS
Installs native Windows release binaries as the dedicated virtual SCM service.
.DESCRIPTION
Run elevated on a supported 64-bit Windows host. OperatorAccount and HarnessAccount
must already exist and be distinct. S4U effective group retrieval must succeed;
privileged groups (including nested/deny-only groups) and elevated local-policy
privileges are rejected for the harness. Custom delegated ACLs, domain delegation,
third-party elevation, future group/policy changes, and administrator compromise
remain operator audit responsibilities. No account memberships are changed.

WER reporting is excluded for these executable basenames. App-specific LocalDumps
is redirected to a managed, deny-write sink, overriding a global LocalDumps folder.
This is not protection against administrators/SYSTEM changing policy or ACLs,
external dump/debug tools, kernel/crash dumps, paging, hibernation, or prior dumps.
The settings apply by basename, not executable path. Existing app-specific WER
settings cause refusal rather than being overwritten. Other applications are untouched.
A failed partial install stays managed and disabled for uninstall.ps1 recovery.
.EXAMPLE
.\scripts\install.ps1 -BinDirectory .\target\release -OperatorAccount '.\brokerop' -HarnessAccount '.\brokerharness'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $BinDirectory,
    [Parameter(Mandatory)][string] $OperatorAccount,
    [Parameter(Mandatory)][string] $HarnessAccount
)
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-BrokerAdministrator
$operatorSid = Assert-BrokerUser $OperatorAccount
$harnessSid = Assert-BrokerUser $HarnessAccount
if ($operatorSid -eq $harnessSid) { throw 'Operator and harness must be distinct user accounts.' }
Assert-BrokerHarness $harnessSid
Assert-BrokerPlainPath $script:BrokerRoot
$source = (Resolve-Path -LiteralPath $BinDirectory).ProviderPath
$names = @('ssh-brokerd.exe', 'brokerctl.exe', 'broker-ssh.exe')
foreach ($name in $names) {
    $file = Join-Path $source $name
    Assert-BrokerPlainPath $file
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing Windows release binary: $name" }
}
if ((Test-Path -LiteralPath $script:BrokerRoot) -or (Get-BrokerServiceRecord)) { throw 'Installation or service already exists. Use uninstall.ps1 before reinstalling; untracked paths are never adopted.' }
$excluded = Join-Path $script:BrokerWer 'ExcludedApplications'
$dumps = Join-Path $script:BrokerWer 'LocalDumps'
foreach ($name in $names) {
    if ((Test-Path -LiteralPath (Join-Path $dumps $name)) -or ((Test-Path -LiteralPath $excluded) -and $null -ne (Get-ItemProperty -LiteralPath $excluded -Name $name -ErrorAction SilentlyContinue))) { throw 'Existing app-specific WER configuration is not installer-owned; installation refused.' }
}
$serviceSid = Get-BrokerServiceSid
if ($operatorSid -eq $serviceSid -or $harnessSid -eq $serviceSid) { throw 'The service identity must be separate from operator and harness.' }
$image = '"' + (Join-Path $script:BrokerRoot 'ssh-brokerd.exe') + '" --operator-sid ' + $operatorSid + ' --harness-sid ' + $harnessSid
$createdService = $false
$createdRoot = $false
$record = Join-Path $script:BrokerRoot '.managed-install.json'
$state = [ordered]@{ Version=1; Product='ssh-credential-broker-windows'; Root=$script:BrokerRoot; Service=$script:BrokerService; OperatorSid=$operatorSid; HarnessSid=$harnessSid; ServiceSid=$serviceSid; ImagePath=$image; WerManaged=@(); Binaries=$names }
try {
    $null = New-Item -ItemType Directory -Path $script:BrokerRoot
    $createdRoot = $true
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $record -Encoding UTF8
    Set-BrokerDirectoryAcl $script:BrokerRoot @($serviceSid, $operatorSid, $harnessSid)
    foreach ($name in $names) { Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $script:BrokerRoot $name) }
    $sink = Join-Path $script:BrokerRoot 'dump-disabled'
    $null = New-Item -ItemType Directory -Path $sink
    Set-BrokerDirectoryAcl $sink -DenyWrite
    $null = New-Item -Path $excluded -Force
    $null = New-Item -Path $dumps -Force
    foreach ($name in $names) {
        # Record ownership before either registry mutation so partial failure is recoverable.
        $state.WerManaged += $name
        $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $record -Encoding UTF8
        $null = New-ItemProperty -LiteralPath $excluded -Name $name -PropertyType DWord -Value 1
        $key = Join-Path $dumps $name
        $null = New-Item -Path $key
        $null = New-ItemProperty -LiteralPath $key -Name DumpFolder -PropertyType ExpandString -Value $sink
        $null = New-ItemProperty -LiteralPath $key -Name DumpCount -PropertyType DWord -Value 1
        $null = New-ItemProperty -LiteralPath $key -Name DumpType -PropertyType DWord -Value 1
    }
    Invoke-BrokerSc @('create', $script:BrokerService, 'binPath=', $image, 'obj=', ('NT SERVICE\' + $script:BrokerService), 'password=', '', 'start=', 'disabled', 'DisplayName=', 'SSH credential broker')
    $createdService = $true
    Invoke-BrokerSc @('sidtype', $script:BrokerService, 'unrestricted')
    Invoke-BrokerSc @('privs', $script:BrokerService, 'SeChangeNotifyPrivilege')
    # Operator can query service state, but cannot replace/start/stop/reconfigure it.
    $sddl = 'D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;' + $operatorSid + ')'
    Invoke-BrokerSc @('sdset', $script:BrokerService, $sddl)
    Invoke-BrokerSc @('config', $script:BrokerService, 'start=', 'auto')
    Invoke-BrokerSc @('start', $script:BrokerService)
    Wait-BrokerServiceState 'Running'
    [ordered]@{ installed=$true; service=$script:BrokerService; root=$script:BrokerRoot; startsLocked=$true; wer='excluded; local dumps denied by managed sink ACL'; privilegeAudit='S4U effective SIDs plus local LSA rights; custom ACL/delegation and future changes require operator audit' } | ConvertTo-Json -Compress
} catch {
    $inner = $_.Exception
    while ($inner.InnerException) { $inner = $inner.InnerException }
    $installStage = if ($createdService) { 'service_configuration_or_startup' } elseif ($createdRoot) { 'directory_or_wer_configuration' } else { 'precondition' }
    $installError = "install_stage_${installStage}: line $($_.InvocationInfo.ScriptLineNumber), $($inner.GetType().Name): $($_.FullyQualifiedErrorId)"
    if ($createdService) { Stop-Service -Name $script:BrokerService -ErrorAction SilentlyContinue; Set-Service -Name $script:BrokerService -StartupType Disabled -ErrorAction SilentlyContinue }
    if ($createdRoot -and -not (Test-Path -LiteralPath $record)) {
        if (@(Get-ChildItem -LiteralPath $script:BrokerRoot -Force).Count -eq 0) { Remove-Item -LiteralPath $script:BrokerRoot }
    }
    throw "Windows installation did not complete ($installError). Any managed partial installation remains stopped/disabled; use uninstall.ps1 to remove it. No account memberships were changed."
}
