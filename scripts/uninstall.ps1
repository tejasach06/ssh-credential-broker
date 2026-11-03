<#
.SYNOPSIS
Removes only the installer-owned native Windows service, binaries and dump policy.
.DESCRIPTION
Run elevated. Operator/harness accounts and memberships are never removed or changed.
Unrecognized service configuration, reparse points, modified WER ownership, or
unexpected installation-directory contents cause refusal. No recursive deletion is
used. Existing global WER policy and unrelated application entries are preserved.
#>
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-BrokerAdministrator
if (-not (Test-Path -LiteralPath $script:BrokerRoot) -and -not (Get-BrokerServiceRecord)) {
    [ordered]@{ removed=$false; reason='not installed' } | ConvertTo-Json -Compress
    return
}
$state = Get-BrokerManagedState
$names = @('ssh-brokerd.exe', 'brokerctl.exe', 'broker-ssh.exe')
if (@($state.Binaries).Count -ne 3 -or @($state.Binaries | Where-Object { $_ -notin $names }).Count -ne 0) { throw 'Unrecognized managed file inventory.' }
$allowed = @($names) + @('.managed-install.json', 'dump-disabled')
foreach ($item in Get-ChildItem -LiteralPath $script:BrokerRoot -Force) {
    if ($item.Name -notin $allowed -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected install-directory content; nothing was removed.' }
    if ($item.PSIsContainer -and $item.Name -ne 'dump-disabled') { throw 'Unexpected installation directory; nothing was removed.' }
}
$sink = Join-Path $script:BrokerRoot 'dump-disabled'
if ((Test-Path -LiteralPath $sink) -and @(Get-ChildItem -LiteralPath $sink -Force).Count -ne 0) { throw 'Dump sink contains unexpected files; nothing was removed.' }
$excluded = Join-Path $script:BrokerWer 'ExcludedApplications'
$dumps = Join-Path $script:BrokerWer 'LocalDumps'
foreach ($name in @($state.WerManaged)) {
    if ($name -notin $names) { throw 'Unrecognized managed dump-policy inventory.' }
    $value = Get-ItemProperty -LiteralPath $excluded -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $value -and $value.$name -ne 1) { throw 'Application exclusion changed outside the installer; nothing was removed.' }
    $key = Join-Path $dumps $name
    if (Test-Path -LiteralPath $key) {
        $values = Get-ItemProperty -LiteralPath $key
        $properties = @((Get-Item -LiteralPath $key).GetValueNames())
        if (@(Get-ChildItem -LiteralPath $key).Count -ne 0 -or @($properties | Where-Object { $_ -notin @('DumpFolder','DumpCount','DumpType') }).Count -ne 0) { throw 'Application dump policy has unrelated content; nothing was removed.' }
        # A partially installed key may contain only a prefix of the managed values.
        if (($properties -contains 'DumpFolder' -and $values.DumpFolder -cne $sink) -or ($properties -contains 'DumpCount' -and $values.DumpCount -ne 1) -or ($properties -contains 'DumpType' -and $values.DumpType -ne 1)) { throw 'Application dump policy changed outside the installer; nothing was removed.' }
    }
}
$service = Get-BrokerServiceRecord
if ($service) {
    Stop-Service -Name $script:BrokerService
    Wait-BrokerServiceState 'Stopped'
    Invoke-BrokerSc @('delete', $script:BrokerService)
    $deadline = [datetime]::UtcNow.AddSeconds(30)
    while (Get-BrokerServiceRecord) {
        if ([datetime]::UtcNow -ge $deadline) { throw 'Service deletion is pending; close service-management handles and rerun uninstall.ps1. Files were retained.' }
        Start-Sleep -Milliseconds 200
    }
}
foreach ($name in @($state.WerManaged)) {
    if (Get-ItemProperty -LiteralPath $excluded -Name $name -ErrorAction SilentlyContinue) { Remove-ItemProperty -LiteralPath $excluded -Name $name }
    $key = Join-Path $dumps $name
    if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key }
}
foreach ($name in $names) {
    $file = Join-Path $script:BrokerRoot $name
    if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
}
if (Test-Path -LiteralPath $sink) { Set-BrokerDirectoryAcl $sink; Remove-Item -LiteralPath $sink -Force }
Remove-Item -LiteralPath (Join-Path $script:BrokerRoot '.managed-install.json') -Force
Remove-Item -LiteralPath $script:BrokerRoot -Force
[ordered]@{ removed=$true; service=$script:BrokerService; accountsChanged=$false } | ConvertTo-Json -Compress
