<#
.SYNOPSIS
Private localhost OpenSSH fixture for an ephemeral elevated Windows runner only.
.DESCRIPTION
Invoked by smoke-windows.ps1 -ProvisionLocalSshFixture. Uses the genuine Windows
OpenSSH server, not a protocol mock. Missing OpenSSH.Server capability is installed
and removed only if this run added it. Requires Git for Windows with bin/bash.exe
and usr/bin/{cat,id,stty,sleep}. Uses a unique SYSTEM scheduled task running sshd -D
on loopback/high port. Existing sshd processes cause refusal; no existing service
configuration is replaced. DefaultShell/DefaultShellCommandOption are backed up
in memory and restored. All fixture files, SSH host private keys and DEBUG3 server
logs are administrator+SYSTEM only. Those endpoint-side logs necessarily contain
the disposable endpoint username; they are never emitted or made harness-readable.
The broker username/password are generated and delivered entirely in memory.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string] $BinDirectory, [Parameter(Mandatory)][switch] $DisposableMachine)
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-BrokerAdministrator
if (-not $DisposableMachine) { throw 'This fixture is allowed only on an explicitly disposable Windows VM.' }
$stage='fixture_prerequisites'
$result='failed'
$failure=$null
$work=$null
$task=$null
$taskRegistered=$false
$createdUser=$null
$createdUserSid=$null
$addedCapability=$false
$createdSshDirectory=$false
$shellChanged=$false
$shellKey='HKLM:\SOFTWARE\OpenSSH'
$shellKeyExisted=Test-Path -LiteralPath $shellKey
$shellBackup=@{}
$cleanup=[Collections.Generic.List[string]]::new()
$smokeReports=[Collections.Generic.List[string]]::new()
function Assert-Fixture([bool] $Value) { if (-not $Value) { throw 'fixture_precondition_failed' } }
function Remove-FixtureTree([string] $Path) {
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
        if ($item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Remove-FixtureTree $item.FullName }
        else { Remove-Item -LiteralPath $item.FullName -Force }
    }
    Remove-Item -LiteralPath $Path -Force
}
try {
    $stage='prerequisite_native_helper_compilation'
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-native.cs')
    $stage='prerequisite_no_existing_broker'
    Assert-Fixture (-not (Test-Path -LiteralPath $script:BrokerRoot) -and -not (Get-BrokerServiceRecord))
    $stage='prerequisite_no_existing_sshd'
    Assert-Fixture (@(Get-Process -Name sshd -ErrorAction SilentlyContinue).Count -eq 0)
    $stage='prerequisite_git_discovery'
    $gitCandidates=@((Join-Path $env:ProgramFiles 'Git\bin\bash.exe'))
    $gitCommand=Get-Command git.exe -ErrorAction SilentlyContinue
    if ($gitCommand) { $gitCandidates += Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($gitCommand.Source))) 'bin\bash.exe' }
    $bash=@($gitCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
    $stage='prerequisite_git_bash_exists'
    Assert-Fixture ($bash.Count -eq 1)
    $bash=[string]$bash[0]
    $stage='prerequisite_git_bash_plain_path'
    Assert-BrokerPlainPath $bash
    $gitRoot=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($bash))
    foreach ($tool in @('cat.exe','id.exe','stty.exe','sleep.exe')) {
        $stage='prerequisite_git_tool_' + [IO.Path]::GetFileNameWithoutExtension($tool)
        Assert-Fixture (Test-Path -LiteralPath (Join-Path $gitRoot ('usr\bin\'+$tool)) -PathType Leaf)
    }
    $stage='prerequisite_windows_sshd_discovery'
    $sshd=Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    if (-not (Test-Path -LiteralPath $sshd -PathType Leaf)) {
        $stage='prerequisite_openssh_capability_query'
        $feature=Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        Assert-Fixture ($feature.State -ne 'Installed')
        $addedCapability=$true
        $stage='install_windows_openssh_capability'
        $installation=Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        $stage='prerequisite_installed_sshd_without_reboot'
        Assert-Fixture (-not $installation.RestartNeeded -and (Test-Path -LiteralPath $sshd -PathType Leaf))
    }
    $stage='prerequisite_no_existing_sshd_after_install'
    Assert-Fixture (@(Get-Process -Name sshd -ErrorAction SilentlyContinue).Count -eq 0)
    $stage='prerequisite_keygen_discovery'
    $keygen=Join-Path ([IO.Path]::GetDirectoryName($sshd)) 'ssh-keygen.exe'
    Assert-Fixture (Test-Path -LiteralPath $keygen -PathType Leaf)
    $stage='create_private_fixture'
    $work=Join-Path $env:ProgramData ('ssh-broker-endpoint-' + [guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $work
    Set-BrokerDirectoryAcl $work
    # Windows OpenSSH privilege-separation support expects this conventional directory.
    # Never replace or rewrite an existing directory or its contents/ACL.
    $sshDirectory=Join-Path $env:ProgramData 'ssh'
    Assert-BrokerPlainPath $sshDirectory
    if (-not (Test-Path -LiteralPath $sshDirectory)) {
        $null=New-Item -ItemType Directory -Path $sshDirectory
        $createdSshDirectory=$true
        Set-BrokerDirectoryAcl $sshDirectory
    }
    $name='sbs' + [guid]::NewGuid().ToString('N').Substring(0,12)
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    $random=[byte[]]::new(36)
    try { $rng.GetBytes($random); $password=ConvertTo-SecureString ('aA1!' + [Convert]::ToBase64String($random)) -AsPlainText -Force }
    finally { [Array]::Clear($random,0,$random.Length); $rng.Dispose() }
    $user=New-LocalUser -Name $name -Password $password -AccountNeverExpires -Description 'Disposable broker SSH endpoint fixture'
    $createdUser=$name; $createdUserSid=$user.SID.Value
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID -eq $user.SID }).Count -eq 0) { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user }
    # Server 2025 may gate remote SSH on this local group. Only the created account is added.
    $sshUsers=Get-LocalGroup -Name 'OpenSSH Users' -ErrorAction SilentlyContinue
    if ($sshUsers) { Add-LocalGroupMember -SID $sshUsers.SID -Member $name }
    $remote=[pscredential]::new($name,$password)
    $hostKey=Join-Path $work 'host_ed25519'
    $generated=[BrokerWindowsNative]::RunPrivate($keygen,@('-q','-t','ed25519','-N','','-f',$hostKey),[byte[]]@(),$false,30)
    Assert-Fixture ($generated.ExitCode -eq 0)
    $fingerprinted=[BrokerWindowsNative]::RunPrivate($keygen,@('-lf',($hostKey+'.pub'),'-E','sha256'),[byte[]]@(),$false,30)
    Assert-Fixture ($fingerprinted.ExitCode -eq 0)
    $fingerprint=([Text.Encoding]::UTF8.GetString($fingerprinted.Stdout) -split '\s+')[1]
    Assert-Fixture ($fingerprint -match '^SHA256:[A-Za-z0-9+/]+={0,2}$')
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $listener.Start(); $port=([Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop()
    $config=Join-Path $work 'sshd_config'
    $log=Join-Path $work 'sshd-audit.log'
    $hostKeyConfig=$hostKey.Replace('\','/')
    $pidConfig=(Join-Path $work 'sshd.pid').Replace('\','/')
    @"
Port $port
ListenAddress 127.0.0.1
HostKey "$hostKeyConfig"
PidFile "$pidConfig"
PasswordAuthentication yes
AuthenticationMethods password
KbdInteractiveAuthentication no
PubkeyAuthentication no
PermitEmptyPasswords no
AllowUsers $name
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
X11Forwarding no
PermitUserEnvironment no
PermitTTY yes
UseDNS no
PrintMotd no
LogLevel DEBUG3
SyslogFacility LOCAL0
"@ | Set-Content -LiteralPath $config -Encoding Ascii
    $stage='validate_real_system_sshd_configuration'
    $validated=[BrokerWindowsNative]::RunPrivate($sshd,@('-t','-f',$config),[byte[]]@(),$false,30)
    Assert-Fixture ($validated.ExitCode -eq 0)
    foreach ($property in @('DefaultShell','DefaultShellCommandOption')) {
        $key=if ($shellKeyExisted) { Get-Item -LiteralPath $shellKey } else { $null }
        $exists=$key -and $property -in $key.GetValueNames()
        $shellBackup[$property]=@{Exists=[bool]$exists;Value=$null;Kind=$null}
        if ($exists) { $shellBackup[$property].Value=$key.GetValue($property,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $shellBackup[$property].Kind=$key.GetValueKind($property).ToString() }
    }
    if (-not $shellKeyExisted) { $null=New-Item -Path $shellKey }
    $shellChanged=$true
    $null=New-ItemProperty -LiteralPath $shellKey -Name DefaultShell -PropertyType String -Value $bash -Force
    $null=New-ItemProperty -LiteralPath $shellKey -Name DefaultShellCommandOption -PropertyType String -Value '-c' -Force
    # Task source and audit reader contain only nonsecret paths/configuration.
    $launcher=Join-Path $work 'run-sshd.ps1'
    $sshdLiteral=$sshd.Replace("'","''"); $configLiteral=$config.Replace("'","''"); $logLiteral=$log.Replace("'","''")
    $sshBinLiteral=([IO.Path]::GetDirectoryName($sshd)).Replace("'","''")
    $gitBinLiteral=(Join-Path $gitRoot 'usr\bin').Replace("'","''")
    @"
`$ErrorActionPreference='Stop'
`$env:PATH='$sshBinLiteral;$gitBinLiteral;' + `$env:SystemRoot + '\System32;' + `$env:SystemRoot
& '$sshdLiteral' -D -E '$logLiteral' -f '$configLiteral' *> `$null
exit `$LASTEXITCODE
"@ | Set-Content -LiteralPath $launcher -Encoding UTF8
    $audit=Join-Path $work 'count-password-submissions.ps1'
    @"
`$ErrorActionPreference='Stop'
`$path='$logLiteral'
if (-not (Test-Path -LiteralPath `$path)) { throw 'Endpoint audit log missing.' }
`$file=[IO.File]::Open(`$path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
try {
    `$reader=[IO.StreamReader]::new(`$file)
    try { `$text=`$reader.ReadToEnd() } finally { `$reader.Dispose() }
} finally { `$file.Dispose() }
[long]([regex]::Matches(`$text,'(?m)^.*\buserauth-request\b[^\r\n]*\bmethod password\b').Count)
"@ | Set-Content -LiteralPath $audit -Encoding UTF8
    $task='ssh-broker-fixture-' + [guid]::NewGuid().ToString('N')
    $arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + [BrokerWindowsNative]::Quote($launcher)
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments -WorkingDirectory $work
    $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::FromMinutes(20)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $null=Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
    $taskRegistered=$true
    $stage='start_real_system_sshd'
    Start-ScheduledTask -TaskName $task
    $deadline=[datetime]::UtcNow.AddSeconds(30)
    do {
        $client=[Net.Sockets.TcpClient]::new()
        try { $client.Connect('127.0.0.1',$port); $ready=$client.Connected } catch { $ready=$false } finally { $client.Dispose() }
        if (-not $ready) { Start-Sleep -Milliseconds 200 }
    } while (-not $ready -and [datetime]::UtcNow -lt $deadline)
    Assert-Fixture $ready
    $fixtureProcesses=@(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($config) })
    Assert-Fixture ($fixtureProcesses.Count -ge 1)
    foreach ($process in $fixtureProcesses) { $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid; Assert-Fixture ($owner.Sid -eq 'S-1-5-18') }
    $rotate = {
        # Rotate only this fixture's independently generated host key. The audit
        # file is append-only across the genuine server restart.
        Stop-ScheduledTask -TaskName $task
        $stopping=[datetime]::UtcNow.AddSeconds(15)
        while ((Get-ScheduledTask -TaskName $task).State -eq 'Running') {
            if ([datetime]::UtcNow -ge $stopping) { throw 'fixture_rotation_stop_failed' }
            Start-Sleep -Milliseconds 100
        }
        $processes=@(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($work) })
        foreach ($process in $processes) { Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue }
        $newKey=Join-Path $work 'host_ed25519_rotated'
        $generated=[BrokerWindowsNative]::RunPrivate($keygen,@('-q','-t','ed25519','-N','','-f',$newKey),[byte[]]@(),$false,30)
        if ($generated.ExitCode -ne 0) { throw 'fixture_rotation_failed' }
        $fingerprinted=[BrokerWindowsNative]::RunPrivate($keygen,@('-lf',($newKey+'.pub'),'-E','sha256'),[byte[]]@(),$false,30)
        if ($fingerprinted.ExitCode -ne 0) { throw 'fixture_rotation_failed' }
        $newPin=([Text.Encoding]::UTF8.GetString($fingerprinted.Stdout) -split '\s+')[1]
        $updated=(Get-Content -LiteralPath $config -Raw).Replace($hostKeyConfig,$newKey.Replace('\','/'))
        Set-Content -LiteralPath $config -Value $updated -Encoding Ascii
        Start-ScheduledTask -TaskName $task
        $until=[datetime]::UtcNow.AddSeconds(30)
        do {
            $client=[Net.Sockets.TcpClient]::new()
            try { $client.Connect('127.0.0.1',$port); $listening=$client.Connected } catch { $listening=$false } finally { $client.Dispose() }
            if (-not $listening) { Start-Sleep -Milliseconds 200 }
        } while (-not $listening -and [datetime]::UtcNow -lt $until)
        if (-not $listening) { throw 'fixture_rotation_failed' }
        return $newPin
    }.GetNewClosure()
    $stage='native_service_and_real_ssh_smoke'
    & (Join-Path $PSScriptRoot 'smoke-windows.ps1') -CreateDisposableAccounts -BinDirectory $BinDirectory -DisposableMachine -DisposableEndpoint -EndpointHost '127.0.0.1' -Port $port -PinnedAddress '127.0.0.1' -HostKeyFingerprint $fingerprint -RemoteCredential $remote -AuthenticationAuditScript $audit -RotateHostKey $rotate | ForEach-Object { $smokeReports.Add([string]$_) }
    $result='passed'
} catch {
    $failure=[ordered]@{exceptionType=$_.Exception.GetType().FullName;scriptLine=$_.InvocationInfo.ScriptLineNumber}
    $result='failed'
} finally {
    if ($taskRegistered) {
        try { Stop-ScheduledTask -TaskName $task; Unregister-ScheduledTask -TaskName $task -Confirm:$false } catch { $cleanup.Add('fixture_task_removal_failed') }
    }
    if ($work) {
        try {
            # Foreground parent and Windows privilege-separation children carry this
            # unique config path. Kill only processes belonging to the created fixture.
            $owned=@(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($work) })
            $ownedPids=@($owned | ForEach-Object ProcessId)
            foreach ($process in $owned) { Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue }
            # Children may omit -f. Their parent chain must reach an owned sshd PID.
            $descendants=@(Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -in $ownedPids })
            foreach ($child in $descendants) { Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue }
        } catch { $cleanup.Add('fixture_process_removal_failed') }
    }
    if ($shellChanged) {
        try {
            foreach ($property in $shellBackup.Keys) {
                $saved=$shellBackup[$property]
                if ($saved.Exists) { $null=New-ItemProperty -LiteralPath $shellKey -Name $property -PropertyType $saved.Kind -Value $saved.Value -Force }
                elseif (Get-ItemProperty -LiteralPath $shellKey -Name $property -ErrorAction SilentlyContinue) { Remove-ItemProperty -LiteralPath $shellKey -Name $property }
            }
            if (-not $shellKeyExisted -and (Get-Item -LiteralPath $shellKey).GetValueNames().Count -eq 0 -and @(Get-ChildItem -LiteralPath $shellKey).Count -eq 0) { Remove-Item -LiteralPath $shellKey }
        } catch { $cleanup.Add('default_shell_restore_failed') }
    }
    if ($createdUser) {
        try {
            $profiles=@(Get-CimInstance Win32_UserProfile -Filter ("SID='"+$createdUserSid+"'"))
            foreach ($profile in $profiles) { Assert-Fixture (-not $profile.Loaded); Remove-CimInstance -InputObject $profile }
            Remove-LocalUser -Name $createdUser
        } catch { $cleanup.Add('fixture_account_profile_removal_failed') }
    }
    if ($work -and (Test-Path -LiteralPath $work)) { try { Remove-FixtureTree $work } catch { $cleanup.Add('private_fixture_removal_failed') } }
    if ($createdSshDirectory -and (Test-Path -LiteralPath $sshDirectory)) {
        try { if (@(Get-ChildItem -LiteralPath $sshDirectory -Force).Count -eq 0) { Remove-Item -LiteralPath $sshDirectory } else { $cleanup.Add('created_openssh_directory_not_empty') } } catch { $cleanup.Add('created_openssh_directory_removal_failed') }
    }
    if ($addedCapability) {
        try { $removed=Remove-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'; if ($removed.RestartNeeded) { $cleanup.Add('openssh_capability_removal_requires_reboot') } } catch { $cleanup.Add('openssh_capability_removal_failed') }
    }
}
if ($cleanup.Count -gt 0) { $result='failed' }
$nested=$null
if ($smokeReports.Count -gt 0) { try { $nested=$smokeReports[$smokeReports.Count-1] | ConvertFrom-Json } catch { $result='failed' } }
[ordered]@{fixture='real-localhost-windows-openssh';result=$result;stage=$stage;failure=$failure;smoke=$nested;cleanup=if ($cleanup.Count -eq 0) {'passed'} else {@($cleanup)}} | ConvertTo-Json -Depth 12 -Compress
if ($result -ne 'passed') { throw 'Local native SSH fixture/smoke failed; see secret-free structured report.' }
