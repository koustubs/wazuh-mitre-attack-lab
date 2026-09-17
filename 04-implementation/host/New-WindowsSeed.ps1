#requires -Version 5.1
<#
Builds an unattended-setup ISO for the Windows endpoint.

Windows Setup scans attached media for autounattend.xml at the root, so this only needs to be a
plain data ISO. The file carries the local account password, so it is written into .lab-secrets
and never committed.

The edition key below is Microsoft's published generic Volume License Setup Key for Windows 11
Pro. It selects the edition during setup and does not activate anything, so the VM runs
unactivated. That is fine for a disposable lab.
#>
[CmdletBinding()]
param(
    [string]$SecretsPath = (Join-Path $PSScriptRoot '.lab-secrets'),
    [string]$ComputerName = 'WAZUH-WIN',
    [string]$Address = '172.29.70.20',
    [string]$Gateway = '172.29.70.1'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$password = (Get-Content (Join-Path $SecretsPath 'console-password.txt') -Raw).Trim()
if ($password -notmatch '^[A-Za-z0-9]+$') { throw 'Password must be alphanumeric so it is safe to embed in XML.' }

if (-not ('LabIso' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class LabIso {
    public static void Write(object image, string path) {
        IStream stream = (IStream)image;
        using (FileStream file = File.Create(path)) {
            byte[] buffer = new byte[2048];
            IntPtr read = Marshal.AllocHGlobal(4);
            try {
                int count;
                do {
                    stream.Read(buffer, buffer.Length, read);
                    count = Marshal.ReadInt32(read);
                    if (count > 0) { file.Write(buffer, 0, count); }
                } while (count == buffer.Length);
            } finally { Marshal.FreeHGlobal(read); }
        }
    }
}
'@
}

# First logon can run before the synthetic NIC reports Up, in which case the adapter lookup
# returns nothing and the address is never applied, leaving the endpoint on an APIPA address.
# Wait for the adapter instead of assuming it is ready.
$network = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"`$a = `$null; for (`$i = 0; `$i -lt 30 -and -not `$a; `$i++) { `$a = Get-NetAdapter | Where-Object { `$_.Status -eq 'Up' } | Select-Object -First 1; if (-not `$a) { Start-Sleep -Seconds 2 } }; if (`$a) { Set-NetIPInterface -InterfaceIndex `$a.ifIndex -Dhcp Disabled; New-NetIPAddress -InterfaceIndex `$a.ifIndex -IPAddress $Address -PrefixLength 24 -DefaultGateway $Gateway; Set-DnsClientServerAddress -InterfaceIndex `$a.ifIndex -ServerAddresses 1.1.1.1,8.8.8.8 }`""

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add"><Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value></MetaData>
          </InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <ProductKey><Key>W269N-WFGWX-YVC9B-4J6C9-T83GX</Key><WillShowUI>OnError</WillShowUI></ProductKey>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>$ComputerName</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>labadmin</Name>
            <DisplayName>labadmin</DisplayName>
            <Group>Administrators</Group>
            <Password><Value>$password</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Username>labadmin</Username>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Password><Value>$password</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Description>Static lab address</Description>
          <CommandLine>$network</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"@

$staging = Join-Path ([IO.Path]::GetTempPath()) 'labseed-windows'
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging | Out-Null
[IO.File]::WriteAllText((Join-Path $staging 'autounattend.xml'), $xml, (New-Object Text.UTF8Encoding($false)))

# Fail here rather than halfway through a Windows install.
[void][xml](Get-Content (Join-Path $staging 'autounattend.xml') -Raw)

$outputDir = Join-Path $SecretsPath 'seeds'
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$iso = Join-Path $outputDir 'windows-unattend.iso'
if (Test-Path $iso) { Remove-Item $iso -Force }

$image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$image.FileSystemsToCreate = 3
$image.VolumeName = 'UNATTEND'
$image.Root.AddTree($staging, $false)
[LabIso]::Write($image.CreateResultImage().ImageStream, $iso)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($image)
Remove-Item $staging -Recurse -Force

Write-Output ("windows-unattend.iso -> {0} bytes (XML validated)" -f (Get-Item $iso).Length)
