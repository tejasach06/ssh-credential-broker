# Executed under the actual operator/harness logon. Requests arrive on an anonymous
# stdin pipe, never command-line/environment/file credentials. Do not enable tracing.
[CmdletBinding()]
param([Parameter(Mandatory)][string] $InstallRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$inputBytes = $null
try {
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-native.cs')
    $stream = [Console]::OpenStandardInput()
    $header = [byte[]]::new(4)
    $offset = 0
    while ($offset -lt 4) { $count = $stream.Read($header, $offset, 4 - $offset); if ($count -eq 0) { throw 'Missing request frame.' }; $offset += $count }
    $length = ([uint32]$header[0] -shl 24) -bor ([uint32]$header[1] -shl 16) -bor ([uint32]$header[2] -shl 8) -bor [uint32]$header[3]
    if ($length -eq 0 -or $length -gt 16MB) { throw 'Request size outside smoke limits.' }
    $buffer = [byte[]]::new($length)
    try {
        $offset = 0
        while ($offset -lt $length) { $count = $stream.Read($buffer, $offset, $length - $offset); if ($count -eq 0) { throw 'Truncated request.' }; $offset += $count }
        $request = [Text.Encoding]::UTF8.GetString($buffer) | ConvertFrom-Json
    } finally { [Array]::Clear($buffer, 0, $buffer.Length) }
    if ($request.mode -eq 'probe') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $checks = [ordered]@{
            actualSid = $identity.User.Value
            processReadDenied = [BrokerWindowsNative]::DeniedProcessRead([int]$request.daemonPid)
            debuggerDenied = [BrokerWindowsNative]::DeniedDebugger([int]$request.daemonPid)
            tokenDuplicationDenied = [BrokerWindowsNative]::DeniedTokenDuplicate([int]$request.daemonPid)
            serviceManagementDenied = [BrokerWindowsNative]::DeniedServiceChange()
            pathChangesDenied = $true
        }
        foreach ($name in @('ssh-brokerd.exe', 'brokerctl.exe', 'broker-ssh.exe', '.managed-install.json')) {
            $path = Join-Path $InstallRoot $name
            # Independently request data-write, delete, change-DACL and take-ownership.
            foreach ($access in @([uint32]2, [uint32]0x10000, [uint32]0x40000, [uint32]0x80000)) {
                if (-not [BrokerWindowsNative]::DeniedPathAccess($path, $access)) { $checks.pathChangesDenied = $false }
            }
        }
        # FILE_ADD_FILE, FILE_DELETE_CHILD, DELETE, WRITE_DAC and WRITE_OWNER.
        foreach ($access in @([uint32]2, [uint32]0x40, [uint32]0x10000, [uint32]0x40000, [uint32]0x80000)) {
            if (-not [BrokerWindowsNative]::DeniedPathAccess($InstallRoot, $access)) { $checks.pathChangesDenied = $false }
        }
        $commands = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='ssh-brokerd.exe' OR Name='brokerctl.exe' OR Name='broker-ssh.exe'" | ForEach-Object { if ($_.CommandLine) { $_.CommandLine } })
        [ordered]@{ ok=$true; probe=$checks; commandLines=$commands } | ConvertTo-Json -Compress -Depth 5
    } elseif ($request.mode -eq 'conpty') {
        Add-Type -Path (Join-Path $PSScriptRoot 'windows-conpty.cs')
        $consoleResult = [BrokerConsoleSmoke]::Run((Join-Path $InstallRoot 'broker-ssh.exe'), [string[]]$request.arguments, [int]$request.timeout)
        try {
            [ordered]@{
                ok=$true; actualSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                interactive=$consoleResult.Interactive; resize=$consoleResult.Resize
                controlC=$consoleResult.ControlC; exitCode=$consoleResult.ExitCode
                transcript=[Convert]::ToBase64String($consoleResult.Transcript)
            } | ConvertTo-Json -Compress -Depth 4
        } finally { [Array]::Clear($consoleResult.Transcript,0,$consoleResult.Transcript.Length) }
    } elseif ($request.mode -in @('ctl', 'ssh', 'outcomeProbe')) {
        $name = if ($request.mode -eq 'ctl') { 'brokerctl.exe' } else { 'broker-ssh.exe' }
        $inputBytes = [Convert]::FromBase64String([string]$request.input)
        if ($request.mode -eq 'outcomeProbe') {
            $result = [BrokerWindowsNative]::RunOutcomeProbe((Join-Path $InstallRoot $name), [string[]]$request.arguments, [string]$request.variant, [int]$request.timeout)
        } else {
            $result = [BrokerWindowsNative]::RunPrivate((Join-Path $InstallRoot $name), [string[]]$request.arguments, $inputBytes, ($request.mode -eq 'ssh'), [int]$request.timeout)
        }
        [ordered]@{
            ok=$true; actualSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            exitCode=$result.ExitCode; stdout=[Convert]::ToBase64String($result.Stdout)
            stderr=[Convert]::ToBase64String($result.Stderr); outcome=[Convert]::ToBase64String($result.Outcome)
            firstOutputMilliseconds=$result.FirstOutputMilliseconds; durationMilliseconds=$result.DurationMilliseconds
        } | ConvertTo-Json -Compress -Depth 4
    } else { throw 'Unknown smoke operation.' }
} catch {
    # A native API/remote response can contain sensitive data. Never print exceptions.
    [Console]::Out.WriteLine('{"ok":false,"error":"worker_operation_failed"}')
    exit 1
} finally { if ($null -ne $inputBytes) { [Array]::Clear($inputBytes, 0, $inputBytes.Length) } }
