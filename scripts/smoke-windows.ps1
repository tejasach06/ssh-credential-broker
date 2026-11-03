<#
.SYNOPSIS
Disposable native Windows service + real SSH acceptance smoke. Never run on a workstation.
.DESCRIPTION
Requires an elevated 64-bit Windows host, Windows PowerShell 5.1, working local WMI,
and supplied disposable POSIX SSH endpoint with password authentication and cat,
printf, id and sleep. The fingerprint and numeric pinned address must be verified
independently. RemoteCredential is supplied as an in-memory PSCredential, never a
literal password argument, environment variable, or credential file. Disable shell
transcription/debug tracing and external process-input capture for the entire run.

AuthenticationAuditScript is an operator-owned local script, invoked without args,
which returns exactly one nonnegative Int64: the monotonic count of ALL password
submissions to this otherwise idle, dedicated sshd instance (accepted and rejected).
It must read real server-side audit evidence via independent trusted access, not
infer submissions from broker output. It must not print raw logs or credentials.
This is REQUIRED to prove no credentials were submitted before approval. Audit log
collection must be synchronous, not delayed event forwarding. The smoke checks
that the count increases after successful SSH login, preventing constant-zero probes.

Existing mode uses supplied separate Windows user credentials and an already
installed disposable broker. Its grant is intentionally locked/replaced/restarted.
CreateDisposableAccounts mode requires BinDirectory, installs the real service,
creates two temporary ordinary local users and removes ONLY those users and its
own installation in finally. Harness-writable scratch is retained for disposable
host teardown; elevated cleanup never traverses it. Existing installs are refused.
Use only on an ephemeral Windows VM such as an elevated hosted windows-2025 runner.
No existing user or membership is changed. ProvisionLocalSshFixture temporarily
sets and restores OpenSSH DefaultShell on the explicitly disposable machine.

Only secret-free structured JSON is emitted. Real ConPTY interaction verifies shell
I/O, remote stty resize and Ctrl-C; the report lists remaining unexercised checks.
.EXAMPLE
# $remote is created by a trusted in-memory fixture or Get-Credential, not a literal.
.\scripts\smoke-windows.ps1 -CreateDisposableAccounts -BinDirectory .\target\release -DisposableMachine -DisposableEndpoint -EndpointHost 192.0.2.10 -PinnedAddress 192.0.2.10 -HostKeyFingerprint $verifiedFingerprint -RemoteCredential $remote -AuthenticationAuditScript C:\fixture\count-password-submissions.ps1
.EXAMPLE
.\scripts\smoke-windows.ps1 -CreateDisposableAccounts -BinDirectory .\target\x86_64-pc-windows-msvc\release -DisposableMachine -ProvisionLocalSshFixture
#>
[CmdletBinding(DefaultParameterSetName='Existing')]
param(
    [Parameter(Mandatory, ParameterSetName='Existing')][pscredential] $OperatorCredential,
    [Parameter(Mandatory, ParameterSetName='Existing')][pscredential] $HarnessCredential,
    [Parameter(Mandatory, ParameterSetName='Create')][switch] $CreateDisposableAccounts,
    [Parameter(Mandatory, ParameterSetName='Create')][string] $BinDirectory,
    [Parameter(Mandatory)][switch] $DisposableMachine,
    [switch] $ProvisionLocalSshFixture,
    [switch] $DisposableEndpoint,
    [string] $EndpointHost,
    [ValidateRange(1,65535)][int] $Port = 22,
    [string] $PinnedAddress,
    [ValidatePattern('^SHA256:[A-Za-z0-9+/]+={0,2}$')][string] $HostKeyFingerprint,
    [pscredential] $RemoteCredential,
    [string] $AuthenticationAuditScript,
    [scriptblock] $RotateHostKey
)
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-BrokerAdministrator
if ($ProvisionLocalSshFixture) {
    if (-not $CreateDisposableAccounts -or -not $DisposableMachine) { throw 'Local SSH provisioning requires CreateDisposableAccounts and DisposableMachine.' }
    & (Join-Path $PSScriptRoot 'smoke-windows-fixture.ps1') -BinDirectory $BinDirectory -DisposableMachine
    return
}
if (-not $RemoteCredential -or [string]::IsNullOrWhiteSpace($EndpointHost) -or [string]::IsNullOrWhiteSpace($PinnedAddress) -or [string]::IsNullOrWhiteSpace($HostKeyFingerprint) -or [string]::IsNullOrWhiteSpace($AuthenticationAuditScript)) { throw 'Supply a disposable SSH endpoint, independent pin, in-memory RemoteCredential and real AuthenticationAuditScript, or use ProvisionLocalSshFixture.' }
if (-not $DisposableMachine -or -not $DisposableEndpoint) { throw 'Explicit disposable-machine and disposable-endpoint assertions are required.' }
$numericAddress = $null
if (-not [Net.IPAddress]::TryParse($PinnedAddress, [ref]$numericAddress)) { throw 'PinnedAddress must be a verified numeric IP address.' }
$AuthenticationAuditScript = (Resolve-Path -LiteralPath $AuthenticationAuditScript).ProviderPath
Assert-BrokerPlainPath $AuthenticationAuditScript
if ([IO.Path]::GetExtension($AuthenticationAuditScript) -ine '.ps1') { throw 'AuthenticationAuditScript must be an operator-owned PowerShell script.' }
$report = [ordered]@{
    platform='windows'; result='failed'; checks=[Collections.Generic.List[object]]::new()
    notExercised=@('host-key rotation', 'DNS rebinding and alias budgets', 'cached credential renewal', 'admission floods and malformed-frame stress', 'hostile SSH negotiation', 'debugger resistance against administrators/SYSTEM', 'kernel dumps, paging and hibernation confidentiality')
    limits=@('Remote shell commands can reveal their own SSH username; username is not hidden from an authorized remote shell.', 'WER exclusions and a deny-write dump sink are not an administrator/SYSTEM or kernel-dump security boundary.', 'No credential buffers are written to argv, environment, or files; PowerShell/.NET managed strings are not guaranteed zeroized.')
    cleanup='not_started'
}
$active = [Collections.Generic.List[object]]::new()
$createdUsers = [Collections.Generic.List[string]]::new()
$madeInstall = $false
$work = $null
$workerPath = $null
$roleTemp = @{}
$operatorSid = $null
$harnessSid = $null
$secretPassword = $null
$unlockFrame = $null
$currentCheck = 'prerequisites'
function Assert-Smoke([bool] $Condition, [string] $Code) { if (-not $Condition) { throw $Code } }
function Add-Coverage([string] $Name, [hashtable] $Evidence = @{}) { $report.checks.Add([ordered]@{name=$Name; result='passed'; evidence=$Evidence}) }
function New-Frame([byte[]] $Bytes) {
    $frame = [byte[]]::new(4 + $Bytes.Length)
    $frame[0] = ($Bytes.Length -shr 24) -band 255; $frame[1] = ($Bytes.Length -shr 16) -band 255
    $frame[2] = ($Bytes.Length -shr 8) -band 255; $frame[3] = $Bytes.Length -band 255
    [Array]::Copy($Bytes, 0, $frame, 4, $Bytes.Length)
    return ,$frame
}
function Read-AuthCount {
    $values = @(& $AuthenticationAuditScript)
    Assert-Smoke ($values.Count -eq 1) 'audit_must_return_one_integer'
    $count = [long]0
    Assert-Smoke ([long]::TryParse([string]$values[0], [ref]$count) -and $count -ge 0) 'audit_count_invalid'
    return $count
}
function Assert-LocalIsolation([string] $Text) {
    Assert-Smoke (-not $Text.Contains($RemoteCredential.UserName)) 'remote_username_in_local_metadata'
    Assert-Smoke (-not $Text.Contains($script:secretPassword)) 'password_in_local_metadata'
}
function Start-Role([string] $Role, [hashtable] $Request) {
    $credential = if ($Role -eq 'operator') { $OperatorCredential } else { $HarnessCredential }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $info.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + [BrokerWindowsNative]::Quote($workerPath) + ' -InstallRoot ' + [BrokerWindowsNative]::Quote($script:BrokerRoot)
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.LoadUserProfile=$false
    $info.RedirectStandardInput=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $info.WorkingDirectory = $roleTemp[$Role]
    $parts = $credential.UserName -split '\\', 2
    if ($parts.Count -eq 2) { $info.Domain=$parts[0]; $info.UserName=$parts[1] } else { $info.UserName=$credential.UserName }
    $info.Password=$credential.Password
    # Do not inherit CI secrets or the elevated caller's inaccessible TEMP directory.
    $info.EnvironmentVariables.Clear()
    foreach ($key in @('SystemRoot','WINDIR','ProgramFiles','ProgramData','COMSPEC')) { $value=[Environment]::GetEnvironmentVariable($key); if ($value) { $info.EnvironmentVariables[$key]=$value } }
    $info.EnvironmentVariables['PATH']="$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0"
    $info.EnvironmentVariables['TEMP']=$roleTemp[$Role]; $info.EnvironmentVariables['TMP']=$roleTemp[$Role]
    $process = [Diagnostics.Process]::new(); $process.StartInfo=$info
    $null = $process.Start()
    $entry = @{Process=$process; Out=$process.StandardOutput.ReadToEndAsync(); Err=$process.StandardError.ReadToEndAsync(); Role=$Role; Timeout=([int]$Request.timeout + 30)}
    $active.Add($entry)
    $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Request -Compress -Depth 6))
    $frame = New-Frame $bytes
    try { $process.StandardInput.BaseStream.Write($frame,0,$frame.Length); $process.StandardInput.Close() }
    finally { [Array]::Clear($bytes,0,$bytes.Length); [Array]::Clear($frame,0,$frame.Length) }
    return $entry
}
function Complete-Role($Entry) {
    try {
        Assert-Smoke ($Entry.Process.WaitForExit($Entry.Timeout * 1000)) 'worker_deadline_exceeded'
        $text = $Entry.Out.GetAwaiter().GetResult()
        $errorText = $Entry.Err.GetAwaiter().GetResult()
        if ($Entry.Process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($errorText)) {
            $script:workerFailureDetail = @{exitCode=$Entry.Process.ExitCode; err=$errorText; out=$text; role=$Entry.Role}
            Assert-Smoke $false 'worker_failed'
        }
        $value = $text | ConvertFrom-Json
        Assert-Smoke ([bool]$value.ok) 'worker_operation_failed'
        if ($value.PSObject.Properties.Name -contains 'actualSid') {
            $expected = if ($Entry.Role -eq 'operator') { $operatorSid } else { $harnessSid }
            Assert-Smoke ($value.actualSid -eq $expected) 'wrong_logon_identity'
        }
        return $value
    } finally {
        if (-not $Entry.Process.HasExited) { $Entry.Process.Kill(); $Entry.Process.WaitForExit() }
        $Entry.Process.Dispose(); $null=$active.Remove($Entry)
    }
}
function Invoke-Role([string] $Role, [hashtable] $Request) { Complete-Role (Start-Role $Role $Request) }
function Invoke-Ctl([string[]] $Arguments, [byte[]] $InputBytes = @()) {
    $result = Invoke-Role 'operator' @{mode='ctl'; arguments=$Arguments; input=[Convert]::ToBase64String($InputBytes); timeout=40}
    $output = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.stdout))
    $errorOutput = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.stderr))
    Assert-LocalIsolation ($output + $errorOutput)
    Assert-Smoke ($result.exitCode -eq 0) 'operator_request_failed'
    return $output
}
function New-ExecRequest([string] $Command='true', [byte[]] $InputBytes=@(), [int] $Timeout=45) {
    return @{mode='ssh'; arguments=@($EndpointHost,'--port',[string]$Port,'--',$Command); input=[Convert]::ToBase64String($InputBytes); timeout=$Timeout}
}
function Invoke-Exec([string] $Command='true', [byte[]] $InputBytes=@(), [int] $Timeout=45) { Invoke-Role 'harness' (New-ExecRequest $Command $InputBytes $Timeout) }
function Read-Outcome($Result) {
    $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.outcome))
    Assert-LocalIsolation $text
    return ($text | ConvertFrom-Json)
}
function Assert-Error($Result, [string[]] $Codes) {
    Assert-Smoke ($Result.exitCode -eq 125) 'expected_local_failure'
    $outcome = Read-Outcome $Result
    Assert-Smoke ($outcome.outcome -eq 'client_error' -and $outcome.code -in $Codes) 'unexpected_classified_failure'
    Assert-LocalIsolation ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Result.stderr)))
}
function Unlock-Smoke([int] $Ttl=1800) { $null=Invoke-Ctl @('unlock','--ttl-seconds',[string]$Ttl,'--private-json-stdin') $unlockFrame }
function Approve-Smoke([int] $Budget=16) { $null=Invoke-Ctl @('approve',$EndpointHost,'--port',[string]$Port,'--pinned-ip',$PinnedAddress,'--fingerprint',$HostKeyFingerprint,'--attempt-budget',[string]$Budget) }
try {
    $currentCheck='native helper'
    if (-not ('BrokerWindowsNative' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'windows-native.cs') }
    if ($CreateDisposableAccounts) {
        $currentCheck='managed installation precondition'
        Assert-Smoke (-not (Test-Path -LiteralPath $script:BrokerRoot) -and -not (Get-BrokerServiceRecord)) 'existing_install_refused'
        $currentCheck='disposable role account creation'
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $credentials = @()
            foreach ($prefix in @('sbo','sbh')) {
                $name=$prefix + [guid]::NewGuid().ToString('N').Substring(0,12)
                $bytes=[byte[]]::new(36); $random.GetBytes($bytes)
                $secure=ConvertTo-SecureString ('aA1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
                [Array]::Clear($bytes,0,$bytes.Length)
                $localUser=New-LocalUser -Name $name -Password $secure -Description 'Disposable broker role fixture' -AccountNeverExpires
                $createdUsers.Add($name)
                # New-LocalUser does not guarantee membership in Users; add only the new account.
                if (@(Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID -eq $localUser.SID }).Count -eq 0) { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $localUser }
                $credentials += [pscredential]::new(($env:COMPUTERNAME + '\' + $name), $secure)
            }
            $OperatorCredential=$credentials[0]; $HarnessCredential=$credentials[1]
        } finally { $random.Dispose() }
        # Mark before invoking install so its recoverable partial state is cleaned too.
        $madeInstall=$true
        $currentCheck='managed service installation'
        $null=& (Join-Path $PSScriptRoot 'install.ps1') -BinDirectory $BinDirectory -OperatorAccount $OperatorCredential.UserName -HarnessAccount $HarnessCredential.UserName
    }
    $currentCheck='managed service state'
    $state=Get-BrokerManagedState
    $operatorSid=Assert-BrokerUser $OperatorCredential.UserName
    $harnessSid=Assert-BrokerUser $HarnessCredential.UserName
    Assert-Smoke ($operatorSid -eq $state.OperatorSid -and $harnessSid -eq $state.HarnessSid -and $operatorSid -ne $harnessSid) 'installed_principals_mismatch'
    Assert-BrokerHarness $harnessSid
    $currentCheck='protected worker staging'
    $work=Join-Path $env:ProgramData ('ssh-broker-smoke-' + [guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $work
    Set-BrokerDirectoryAcl $work @($operatorSid,$harnessSid)
    foreach ($name in @('smoke-windows-worker.ps1','windows-native.cs','windows-conpty.cs')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $work $name) }
    $workerPath=Join-Path $work 'smoke-windows-worker.ps1'
    $currentCheck='role scratch ACLs'
    foreach ($role in @('operator','harness')) {
        $path=Join-Path $work $role; $null=New-Item -ItemType Directory -Path $path
        Set-BrokerDirectoryAcl $path
        $sid=if ($role -eq 'operator') { $operatorSid } else { $harnessSid }
        $acl=Get-Acl -LiteralPath $path
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'Modify','ContainerInherit, ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $path -AclObject $acl; $roleTemp[$role]=$path
    }
    $currentCheck='private remote credential preparation'
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($RemoteCredential.Password)
    try { $secretPassword=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    Assert-Smoke (-not [string]::IsNullOrEmpty($secretPassword) -and -not [string]::IsNullOrEmpty($RemoteCredential.UserName)) 'empty_remote_credential'
    $payload=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @([ordered]@{username=$RemoteCredential.UserName;password=$secretPassword}) -Compress))
    try { $unlockFrame=New-Frame $payload } finally { [Array]::Clear($payload,0,$payload.Length) }
    $currentCheck='startup_lock_and_identity_boundaries'
    Restart-Service -Name $script:BrokerService
    Wait-BrokerServiceState 'Running'
    Assert-Error (Invoke-Exec) @('BROKER_LOCKED')
    $denied=Invoke-Role 'harness' @{mode='ctl';arguments=@('status');input='';timeout=10}
    Assert-Smoke ($denied.exitCode -eq 125) 'harness_accessed_admin_pipe'
    $deniedAdmin=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($denied.stderr)) | ConvertFrom-Json
    Assert-Smoke ($deniedAdmin.code -in @('TRANSPORT_FAILURE','PERMISSION_DENIED')) 'admin_denial_not_access_boundary'
    Assert-Error (Invoke-Role 'operator' (New-ExecRequest)) @('TRANSPORT_FAILURE','PERMISSION_DENIED')
    Add-Coverage 'startup locked; real harness admin denial; operator exec denial; separate logon SIDs'
    $currentCheck='private_unlock_and_preapproval_audit'
    $before=Read-AuthCount
    Unlock-Smoke
    Assert-Error (Invoke-Exec) @('APPROVAL_REQUIRED')
    $pendingText=Invoke-Ctl @('pending')
    $pending=$pendingText | ConvertFrom-Json
    $matches=@($pending.PendingList | Where-Object { $_.target -eq $EndpointHost -and $_.port -eq $Port -and $_.resolved_ip -eq $PinnedAddress -and $_.host_key_fingerprint -eq $HostKeyFingerprint })
    Assert-Smoke ($matches.Count -eq 1) 'pending_identity_does_not_match_independent_pin'
    $after=Read-AuthCount
    Assert-Smoke ($before -eq $after) 'credential_submitted_before_approval'
    Add-Coverage 'same-SID private in-memory unlock; independent pending key/IP; zero preapproval password submissions' @{passwordSubmissionDelta=($after-$before)}
    $currentCheck='real_ssh_authorization_and_audit_liveness'
    Approve-Smoke
    $executed=Invoke-Exec 'printf AUTHORIZED_OK'
    Assert-Smoke ($executed.exitCode -eq 0 -and [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($executed.stdout)) -ceq 'AUTHORIZED_OK') 'authorized_real_ssh_failed'
    $outcome=Read-Outcome $executed
    Assert-Smoke ($outcome.outcome -eq 'remote_exit' -and $outcome.exit_status -eq 0) 'missing_remote_success_outcome'
    $approvedCount=Read-AuthCount
    Assert-Smoke ($approvedCount -gt $after) 'audit_did_not_observe_successful_password_submission'
    Add-Coverage 'approved real SSH execution and independent audit liveness' @{passwordSubmissionDelta=($approvedCount-$after)}
    $currentCheck='invalid_outcome_handle_preflight_without_authentication'
    $marker='.broker-outcome-' + [guid]::NewGuid().ToString('N')
    Assert-Smoke ((Invoke-Exec ('test ! -e ' + $marker)).exitCode -eq 0) 'remote_probe_marker_already_exists'
    $preflightCount=Read-AuthCount
    foreach ($variant in @('readonly','event','process')) {
        $request=New-ExecRequest ('printf UNEXPECTED > ' + $marker)
        $request.mode='outcomeProbe'; $request.variant=$variant
        $invalid=Invoke-Role 'harness' $request
        $diagnostic=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($invalid.stderr))
        Assert-LocalIsolation $diagnostic
        $errorOutcome=$diagnostic | ConvertFrom-Json
        Assert-Smoke ($invalid.exitCode -eq 125 -and $errorOutcome.code -eq 'LOCAL_IO') 'invalid_outcome_handle_was_not_rejected_locally'
        Assert-Smoke ([Convert]::FromBase64String($invalid.stdout).Length -eq 0 -and (Read-AuthCount) -eq $preflightCount) 'invalid_outcome_handle_submitted_password_or_executed'
    }
    $markerCheck=Invoke-Exec ('if test -e ' + $marker + '; then rm -f ' + $marker + '; exit 1; fi')
    Assert-Smoke ($markerCheck.exitCode -eq 0) 'invalid_outcome_handle_executed_remote_marker'
    Add-Coverage 'readonly disk, event and process outcome handles rejected as LOCAL_IO before authentication or remote marker execution' @{invalidHandleVariants=3;passwordSubmissionDelta=0}
    $currentCheck='credential_username_and_process_isolation'
    $daemon=Get-BrokerServiceRecord
    $probe=Invoke-Role 'harness' @{mode='probe';daemonPid=[int]$daemon.ProcessId;timeout=15}
    Assert-Smoke ($probe.probe.actualSid -eq $harnessSid -and $probe.probe.processReadDenied -and $probe.probe.debuggerDenied -and $probe.probe.tokenDuplicationDenied -and $probe.probe.serviceManagementDenied -and $probe.probe.pathChangesDenied) 'harness_broke_native_security_boundary'
    foreach ($line in $probe.commandLines) { Assert-LocalIsolation ([string]$line) }
    $null=Invoke-Ctl @('status'); $null=Invoke-Ctl @('pending')
    Add-Coverage 'local metadata username/password isolation; daemon VM_READ and DebugActiveProcess denial; token duplicate denial; per-right service and binary/directory replacement denial'
    $currentCheck='streaming_and_binary_status'
    $streamed=Invoke-Exec 'printf STREAM_EARLY; sleep 3; printf STREAM_LATE'
    Assert-Smoke ($streamed.exitCode -eq 0 -and [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($streamed.stdout)) -ceq 'STREAM_EARLYSTREAM_LATE') 'stream_output_corrupted'
    Assert-Smoke ($streamed.firstOutputMilliseconds -ge 0 -and ($streamed.durationMilliseconds-$streamed.firstOutputMilliseconds) -ge 2000) 'output_was_not_streamed_before_remote_exit'
    $binary=[byte[]]::new(1MB)
    for ($index=0; $index -lt $binary.Length; $index++) { $binary[$index]=$index -band 255 }
    $transferred=Invoke-Exec 'cat; printf STDERR_OK >&2; exit 7' $binary
    $received=[Convert]::FromBase64String($transferred.stdout)
    Assert-Smoke ($transferred.exitCode -eq 7 -and $received.Length -eq $binary.Length) 'binary_or_exit_failed'
    $sha=[Security.Cryptography.SHA256]::Create()
    try { Assert-Smoke ([Convert]::ToBase64String($sha.ComputeHash($received)) -ceq [Convert]::ToBase64String($sha.ComputeHash($binary))) 'binary_stream_corrupted' } finally { $sha.Dispose() }
    Assert-Smoke ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($transferred.stderr)) -ceq 'STDERR_OK') 'stderr_stream_corrupted'
    $outcome=Read-Outcome $transferred
    Assert-Smoke ($outcome.outcome -eq 'remote_exit' -and $outcome.exit_status -eq 7) 'remote_nonzero_status_not_preserved'
    Add-Coverage 'real command streaming; 1MiB binary stdin/stdout; EOF; independent stderr and remote exit 7' @{binaryBytes=$binary.Length; earlyOutputLeadMilliseconds=($streamed.durationMilliseconds-$streamed.firstOutputMilliseconds)}
    $currentCheck='remote_username_visibility_boundary'
    $visible=Invoke-Exec 'id -un'
    Assert-Smoke ($visible.exitCode -eq 0 -and [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($visible.stdout)).Trim() -ceq $RemoteCredential.UserName) 'remote_identity_mismatch'
    Assert-Smoke (-not [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($visible.stdout)).Contains($secretPassword)) 'password_exposed_in_remote_output'
    Add-Coverage 'authorized remote shell can identify its own username; no password returned'
    $currentCheck='native_conpty_shell_resize_and_control'
    $console=Invoke-Role 'harness' @{mode='conpty';arguments=@($EndpointHost,'--port',[string]$Port);input='';timeout=75}
    Assert-Smoke ($console.interactive -and $console.resize -and $console.controlC -and $console.exitCode -eq 37) 'conpty_shell_resize_control_or_status_failed'
    $transcript=[Convert]::FromBase64String($console.transcript)
    try { Assert-Smoke (-not [Text.Encoding]::UTF8.GetString($transcript).Contains($secretPassword)) 'password_exposed_in_remote_terminal' }
    finally { [Array]::Clear($transcript,0,$transcript.Length); $console=$null }
    Add-Coverage 'real native ConPTY shell I/O; remote stty initial 24x80 and resize 37x112; Ctrl-C interrupts foreground sleep; remote exit 37'
    $currentCheck='active_lock_revocation'
    $running=Start-Role 'harness' (New-ExecRequest 'printf ACTIVE_LOCK; sleep 30; printf SHOULD_NOT_RUN' @() 45)
    Start-Sleep -Seconds 3
    $null=Invoke-Ctl @('lock')
    $ended=Complete-Role $running
    Assert-Error $ended @('BROKER_LOCK')
    Assert-Smoke ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ended.stdout)) -ceq 'ACTIVE_LOCK') 'lock_did_not_revoke_established_session'
    $lockedCount=Read-AuthCount
    Assert-Error (Invoke-Exec) @('BROKER_LOCKED')
    Assert-Smoke ((Read-AuthCount) -eq $lockedCount) 'locked_request_submitted_password'
    Add-Coverage 'active-session lock revocation; locked request submits no password'
    $currentCheck='restart_erases_unlocked_grant'
    Unlock-Smoke
    Restart-Service -Name $script:BrokerService
    Wait-BrokerServiceState 'Running'
    $restartCount=Read-AuthCount
    Assert-Error (Invoke-Exec) @('BROKER_LOCKED')
    Assert-Smoke ((Read-AuthCount) -eq $restartCount) 'restart_retained_credentials'
    Add-Coverage 'service restart erases unlocked grant and starts locked without password submission'
    if ($RotateHostKey) {
        $currentCheck='changed_host_key_refusal_before_password_submission'
        Unlock-Smoke
        Assert-Error (Invoke-Exec) @('APPROVAL_REQUIRED')
        Approve-Smoke 2
        $rotation=@(& $RotateHostKey)
        Assert-Smoke ($rotation.Count -eq 1 -and [string]$rotation[0] -match '^SHA256:[A-Za-z0-9+/]+={0,2}$' -and [string]$rotation[0] -cne $HostKeyFingerprint) 'rotation_must_return_independent_new_fingerprint'
        $rotationCount=Read-AuthCount
        Assert-Error (Invoke-Exec) @('HOST_KEY_MISMATCH','APPROVAL_REQUIRED')
        Assert-Smoke ((Read-AuthCount) -eq $rotationCount) 'changed_host_key_received_password'
        $HostKeyFingerprint=[string]$rotation[0]
        $report.notExercised=@($report.notExercised | Where-Object { $_ -ne 'host-key rotation' })
        Add-Coverage 'real SSH host-key replacement refused before any password submission; independent replacement pin' @{passwordSubmissionDelta=0}
    }
    $currentCheck='real_ttl_expiry_revocation'
    $null=Invoke-Ctl @('lock')
    Unlock-Smoke 60
    Assert-Error (Invoke-Exec) @('APPROVAL_REQUIRED')
    Approve-Smoke 2
    $expiring=Invoke-Exec 'printf ACTIVE_EXPIRY; sleep 90; printf SHOULD_NOT_RUN' @() 75
    Assert-Error $expiring @('BROKER_EXPIRED')
    Assert-Smoke ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($expiring.stdout)) -ceq 'ACTIVE_EXPIRY') 'expiry_did_not_revoke_established_session'
    $expiryCount=Read-AuthCount
    Assert-Error (Invoke-Exec) @('BROKER_LOCKED')
    Assert-Smoke ((Read-AuthCount) -eq $expiryCount) 'expired_request_submitted_password'
    Add-Coverage 'real 60-second TTL; established channel revoked; later request locked without password submission'
    $report.result='passed'
} catch {
    # No raw exception, CLI output, endpoint login, or credential enters diagnostics.
    $base = $_.Exception
    while ($base.InnerException) { $base = $base.InnerException }
    $report.failure=[ordered]@{
        check=$currentCheck
        code='native_windows_smoke_failed'
        exceptionType=$base.GetType().FullName
        errorId=$_.FullyQualifiedErrorId
        scriptLine=$_.InvocationInfo.ScriptLineNumber
        nativeErrorCode=if ($base -is [ComponentModel.Win32Exception]) { $base.NativeErrorCode } else { $null }
        workerDetail=if ($script:workerFailureDetail) { $script:workerFailureDetail } else { $null }
    }
} finally {
    $cleanupErrors=[Collections.Generic.List[string]]::new()
    foreach ($entry in @($active.ToArray())) {
        try { if (-not $entry.Process.HasExited) { $entry.Process.Kill(); $entry.Process.WaitForExit() }; $entry.Process.Dispose() } catch { $cleanupErrors.Add('worker_cleanup_failed') }
    }
    if ($madeInstall) {
        try { $null=& (Join-Path $PSScriptRoot 'uninstall.ps1') } catch { $cleanupErrors.Add('managed_install_removal_failed') }
    } elseif ($operatorSid -and $workerPath) {
        try { $null=Invoke-Ctl @('lock') } catch { $cleanupErrors.Add('final_lock_failed') }
    }
    if ($null -ne $unlockFrame) { [Array]::Clear($unlockFrame,0,$unlockFrame.Length) }
    $secretPassword=$null
    if ($work) {
        # The harness can race any path/reparse check within its writable scratch.
        # Never traverse or delete that tree as administrator, even after logoff.
        $report.scratchCleanup='retained_for_disposable_host_teardown'
    }
    foreach ($name in $createdUsers) {
        try { Remove-LocalUser -Name $name } catch { $cleanupErrors.Add('disposable_account_removal_failed') }
    }
    if ($cleanupErrors.Count -eq 0) { $report.cleanup='passed' } else { $report.cleanup=@($cleanupErrors); $report.result='failed' }
}
$report | ConvertTo-Json -Depth 8 -Compress
if ($report.result -ne 'passed') { throw 'Native Windows smoke failed; see the secret-free structured report.' }
