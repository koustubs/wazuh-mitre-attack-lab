#requires -Version 5.1
#requires -RunAsAdministrator
<#
Generates a controlled burst of failed logons for one local account, using the same LogonUser
technique as Invoke-Scenario.ps1. The Windows counterpart of s1-burst.sh: it takes the account
and the count as arguments and leaves the account in place, so several bursts can be aimed at
the same account with a chosen gap between them. That is what the frequency edge cases on rule
100101 need, which is frequency 6 within 120 seconds on the same account and domain.

The stock ruleset correlates across bursts here as well, on a different key. 60204 and 60205
are frequency 8 within 240 seconds on win.eventdata.ipAddress, and a local network logon records
that address as "-", so every failure on the endpoint shares it whatever the account. Once any
240 second span holds eight failures, analysisd gives the event to 60204 instead of to 100100,
and 100101 never counts it. Keep a sequence of bursts to seven failures in any 240 seconds, and
read the rule ids rather than counting alerts.

Windows 11 locks an account after ten bad passwords in ten minutes by default. A locked account
fails with 1909 rather than 1326 and the event is no longer the one 100100 matches, so the loop
stops there rather than generating it.

    .\s1-burst.ps1 -Account wzfreqa1 -Count 3
    .\s1-burst.ps1 -Account wzfreqa1 -Remove
#>
[CmdletBinding(DefaultParameterSetName = 'Burst')]
param(
    [Parameter(Mandatory)][ValidatePattern('^wzfreq[a-z0-9]+$')][string]$Account,
    [Parameter(Mandatory, ParameterSetName = 'Burst')][ValidateRange(1, 20)][int]$Count,
    [Parameter(Mandatory, ParameterSetName = 'Remove')][switch]$Remove
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Remove) {
    if (Get-LocalUser -Name $Account -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $Account }
    Write-Output ('REMOVED host={0} user={1}' -f $env:COMPUTERNAME, $Account)
    return
}

if (-not (Get-LocalUser -Name $Account -ErrorAction SilentlyContinue)) {
    $password = ConvertTo-SecureString ('Wz!9' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
    New-LocalUser -Name $Account -Password $password -Description 'Wazuh lab frequency test' | Out-Null
}

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

$started = [DateTime]::UtcNow
for ($i = 0; $i -lt $Count; $i++) {
    $token = [IntPtr]::Zero
    $ok = [WazuhLab.NativeLogon]::LogonUser($Account, $env:COMPUTERNAME, 'DeliberatelyWrong!7', 3, 0, [ref]$token)
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($ok) { [void][WazuhLab.NativeLogon]::CloseHandle($token); throw 'The wrong password unexpectedly succeeded.' }
    if ($code -ne 1326) { throw "Logon returned $code instead of incorrect credentials, after $i failures." }
    Start-Sleep -Seconds 1
}
Write-Output ('BURST host={0} user={1} count={2} started={3} finished={4}' -f $env:COMPUTERNAME, $Account, $Count,
    $started.ToString('yyyy-MM-ddTHH:mm:ssZ'), [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
