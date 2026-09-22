#requires -Version 5.1
<#
    Builds the cloud-init seed for each Ubuntu guest the profile includes.

    Each seed is a small ISO labelled CIDATA holding three files. Cloud-init finds it by that
    label, so it does not matter which drive it lands on:

        user-data       the account, the SSH key, the hostname, the lab env file
        meta-data       the instance identity
        network-config  netplan, written for whichever backend's adapter layout applies

    This used to emit a subiquity autoinstall directive, which is a different thing: it drove
    the Ubuntu server installer, and the installer had to be told to look for it by typing
    "autoinstall" at the GRUB prompt. The guests boot a pre-installed cloud image now, so this
    is plain cloud-init configuring a system that already exists.

    Nothing here is committed. The seeds carry the console password hash and the public key, and
    .lab-secrets is gitignored.

        .\New-LabSeeds.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('lean', 'full')][string]$Profile,
    [ValidateSet('hyperv', 'virtualbox')][string]$Backend,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
. (Join-Path $PSScriptRoot 'LabIso.ps1')

$config = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
$vms    = if ($Profile) { Get-LabVms -Profile $Profile }    else { Get-LabVms }
if (-not $Backend) { $Backend = $config.backend }
if (-not $OutputPath) { $OutputPath = Get-LabPath Seeds }

$secrets = Get-LabPath Secrets
$publicKey = (Get-Content -LiteralPath (Join-Path $secrets 'lab_ed25519.pub') -Raw).Trim()
$passwordHash = (Get-Content -LiteralPath (Join-Path $secrets 'console-password.hash') -Raw).Trim()
if (-not $publicKey.StartsWith('ssh-')) { throw 'The public key in .lab-secrets does not look like one. Run New-LabSecrets.ps1.' }
if (-not $passwordHash.StartsWith('$6$')) { throw 'Expected a SHA-512 crypt hash in console-password.hash. Run New-LabSecrets.ps1.' }

# The same values the guest scripts source, generated once and carried into each seed rather
# than written a second time here.
$envFile = Join-Path ([IO.Path]::GetTempPath()) ('lab-env-' + [guid]::NewGuid().ToString('N') + '.env')
& (Join-Path $PSScriptRoot 'Write-GuestConfig.ps1') -Profile $config.profile -Path $envFile | Out-Null
$labEnv = Get-Content -LiteralPath $envFile -Raw
Remove-Item -LiteralPath $envFile -Force

$network = $config.network
$dns = ($network.dns -join ', ')

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

foreach ($name in $vms.Keys) {
    $vm = $vms[$name]
    if ($vm.Os -ne 'ubuntu') { continue }

    $staging = Join-Path ([IO.Path]::GetTempPath()) ('labseed-' + $vm.Hostname)
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging | Out-Null

    # ---- network-config -----------------------------------------------------------------
    if ($Backend -eq 'virtualbox') {
        $mac = (Get-LabMacAddress -Address $vm.Address -Separator ':').ToLower()
        $networkConfig = @"
version: 2
ethernets:
  outbound:
    match:
      name: "e*"
    dhcp4: true
    dhcp4-overrides:
      use-dns: false
    nameservers:
      addresses: [$dns]
  labnet:
    match:
      macaddress: "$mac"
    dhcp4: false
    addresses:
      - $($vm.Address)/$($network.prefixLength)
"@
    } else {
        $networkConfig = @"
version: 2
ethernets:
  labnet:
    match:
      name: "e*"
    dhcp4: false
    addresses:
      - $($vm.Address)/$($network.prefixLength)
    routes:
      - to: default
        via: $($network.gateway)
    nameservers:
      addresses: [$dns]
"@
    }

    # ---- user-data ----------------------------------------------------------------------
    # The image's own cloud.cfg names "ubuntu" as its default user. Listing users: here without
    # "- default" means cloud-init never creates it, which is the intent: a well known account
    # name on a lab that exists to detect brute force attempts is not something to leave
    # running. The runcmd below locks it anyway, for the case where a future image creates the
    # account somewhere other than cloud-init's default_user.
    $indentedEnv = (($labEnv -split "`n" | ForEach-Object { '      ' + $_ }) -join "`n").TrimEnd()
    $userData = @"
#cloud-config
hostname: $($vm.Hostname)
fqdn: $($vm.Hostname)
prefer_fqdn_over_hostname: false
locale: $($config.guest.locale)
timezone: $($config.guest.timezone)

users:
  - name: $($config.guest.user)
    gecos: Wazuh lab account
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: false
    passwd: "$passwordHash"
    sudo: ALL=(ALL) ALL
    ssh_authorized_keys:
      - "$publicKey"

# Password login over SSH stays off. The console password exists so the VM window is usable
# when the network is the thing that is broken, which is exactly when SSH is not an option.
ssh_pwauth: false
disable_root: true

write_files:
  - path: /etc/wazuh-lab/lab.env
    owner: root:root
    permissions: "0644"
    content: |
$indentedEnv

package_update: true
packages:
  - openssh-server
  - curl
  - ca-certificates

runcmd:
  - [ sh, -c, "id ubuntu >/dev/null 2>&1 && usermod -L ubuntu || true" ]
  - [ systemctl, enable, --now, ssh ]

final_message: "cloud-init finished after `$UPTIME seconds. The lab account and its key are in place."
"@

    $metaData = @"
instance-id: $($vm.Hostname)-01
local-hostname: $($vm.Hostname)
"@

    Write-LabLfFile -Path (Join-Path $staging 'user-data') -Content $userData
    Write-LabLfFile -Path (Join-Path $staging 'meta-data') -Content $metaData
    Write-LabLfFile -Path (Join-Path $staging 'network-config') -Content $networkConfig

    $iso = Join-Path $OutputPath ($vm.Hostname + '-seed.iso')
    New-LabDataIso -SourceDirectory $staging -IsoPath $iso -VolumeName 'CIDATA'
    Remove-Item -LiteralPath $staging -Recurse -Force
    Write-Output ("{0,-24} {1,6} bytes  {2}" -f (Split-Path $iso -Leaf), (Get-Item -LiteralPath $iso).Length, $vm.Address)
}

Write-Output ''
Write-Output ("Seeds for the {0} profile on {1}, in {2}" -f $config.profile, $Backend, $OutputPath)
if ($vms.Contains('WAZUH-WIN')) {
    Write-Output 'The Windows endpoint has its own seed: setup\New-WindowsSeed.ps1'
}
Write-Output 'Next: setup\New-Lab.ps1'
