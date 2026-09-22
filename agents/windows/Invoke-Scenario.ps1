#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('S1', 'S2', 'S3')][string]$Scenario,
    [switch]$Comparison,
    [string]$ExpectedComputerName = 'WAZUH-WIN',
    [string]$OutputDirectory = "$env:ProgramData\WazuhLab\evidence"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ine $ExpectedComputerName) { throw "Run this on the lab endpoint $ExpectedComputerName." }
if ((Get-Service WazuhSvc).Status -ne 'Running') { throw 'Start the Wazuh agent first.' }
$runId = [Guid]::NewGuid().ToString('N').Substring(0, 10)
$name = 'wz' + $runId
$taskName = 'WazuhLab-' + $runId
$start = [DateTime]::UtcNow
$runDir = Join-Path $OutputDirectory "$Scenario-$runId"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$createdUser = $false
$createdTask = $false
$attempts = 0
$failure = $null
try {
    if ($Scenario -in @('S1', 'S2')) {
        $password = ConvertTo-SecureString ('Wz!9' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
        New-LocalUser -Name $name -Password $password -Description "Wazuh lab $runId" | Out-Null
        $createdUser = $true
    }
    if ($Scenario -eq 'S1') {
        if (-not ('WazuhLab.NativeLogon' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace WazuhLab {
    public static class NativeLogon {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool LogonUser(string user, string domain, string password,
            int logonType, int provider, out IntPtr token);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
    }
}
'@
        }
        $attempts = if ($Comparison) { 1 } else { 6 }
        for ($i = 0; $i -lt $attempts; $i++) {
            $token = [IntPtr]::Zero
            $ok = [WazuhLab.NativeLogon]::LogonUser($name, $env:COMPUTERNAME, 'DeliberatelyWrong!7', 3, 0, [ref]$token)
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ok) { [void][WazuhLab.NativeLogon]::CloseHandle($token); throw 'The wrong password unexpectedly succeeded.' }
            if ($code -ne 1326) { throw "Logon returned $code instead of incorrect credentials. Check the test account policy." }
            Start-Sleep -Seconds 1
        }
    } elseif ($Scenario -eq 'S3') {
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument '/c exit 0'
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User 'SYSTEM' -Description "Wazuh lab $runId" | Out-Null
        $createdTask = $true
        Export-ScheduledTask -TaskName $taskName | Set-Content (Join-Path $runDir 'task.xml') -Encoding UTF8
    }
    Start-Sleep -Seconds 3
    $wanted = @{ S1 = 4625; S2 = 4720; S3 = 4698 }[$Scenario]
    $sourceEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $wanted; StartTime = $start.ToLocalTime() } -ErrorAction SilentlyContinue | Where-Object {
        [xml]$eventXml = $_.ToXml()
        $fieldName = if ($Scenario -eq 'S3') { 'TaskName' } else { 'TargetUserName' }
        $value = ($eventXml.Event.EventData.Data | Where-Object { $_.Name -eq $fieldName }).'#text'
        if ($Scenario -eq 'S3') { $value -eq "\$taskName" } else { $value -eq $name }
    })
    foreach ($event in $sourceEvents) { $event.ToXml() | Set-Content (Join-Path $runDir "$($event.RecordId).xml") -Encoding UTF8 }
    $expectedCount = if ($Scenario -eq 'S1') { $attempts } else { 1 }
    if ($sourceEvents.Count -lt $expectedCount) { throw "Captured $($sourceEvents.Count) source events; expected at least $expectedCount. Check audit policy." }
} catch { $failure = $_.Exception.Message }
finally {
    if ($createdTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    if ($createdUser) { Remove-LocalUser -Name $name }
    [ordered]@{
        runId = $runId; platform = 'windows'; scenario = $Scenario
        comparison = [bool]$Comparison; endpoint = $env:COMPUTERNAME
        marker = $(if ($Scenario -eq 'S3') { $taskName } else { $name })
        startedAt = $start.ToString('o'); finishedAt = [DateTime]::UtcNow.ToString('o')
        attemptedLogons = $attempts; sourceEventCount = $(if (Get-Variable sourceEvents -ErrorAction SilentlyContinue) { $sourceEvents.Count } else { 0 })
        error = $failure; indexedDetection = 'not_checked'
    } | ConvertTo-Json | Set-Content (Join-Path $runDir 'run.json') -Encoding UTF8
}
if ($failure) { throw $failure }
Write-Output "Source events saved in $runDir. Check indexed Wazuh alerts to complete this run."
