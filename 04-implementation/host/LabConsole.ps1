#requires -Version 5.1
<#
Headless console access to a Hyper-V VM.

Hyper-V exposes a synthetic keyboard and a framebuffer thumbnail over WMI, so the boot menu can
be driven without opening VMConnect. This is only needed to add "autoinstall" to the kernel
command line, which the Ubuntu installer requires before it will read the cloud-init seed.

Dot-source this file, then use Get-LabScreen and Send-LabKeys.

Two things learned the hard way while using this against Windows Setup:

Keystrokes are buffered. Keys sent while firmware is still loading get delivered once the
application starts, so sending several in the hope of catching a prompt lands them all in
whatever appears next.

In Windows Setup both Enter and Escape activate Cancel, which opens a "quit" dialog. There is no
safe key to spam. Send exactly one key for the "press any key to boot" prompt, then stop.
#>
Set-StrictMode -Version Latest

function Get-LabVmObjects {
    param([Parameter(Mandatory)][string]$VMName)
    $vm = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem `
        -Filter "ElementName='$VMName' AND Caption='Virtual Machine'"
    if (-not $vm) { throw "VM not found: $VMName" }
    $setting = Get-CimAssociatedInstance -InputObject $vm `
        -ResultClassName Msvm_VirtualSystemSettingData | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }
    [pscustomobject]@{ Vm = $vm; Setting = $setting }
}

function Get-LabScreen {
    <# Captures the VM framebuffer and writes it as a PNG. #>
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$Path,
        [int]$Width = 800,
        [int]$Height = 600
    )
    $objects = Get-LabVmObjects -VMName $VMName
    $service = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
    $result = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{
        TargetSystem = [ciminstance]$objects.Setting
        WidthPixels  = [uint16]$Width
        HeightPixels = [uint16]$Height
    }
    if ($result.ReturnValue -ne 0) { throw "Thumbnail capture failed: $($result.ReturnValue)" }
    $data = $result.ImageData
    if (-not $data -or $data.Length -eq 0) { throw 'Thumbnail returned no data. The VM may be off.' }

    Add-Type -AssemblyName System.Drawing
    $bitmap = New-Object Drawing.Bitmap($Width, $Height)
    # The framebuffer comes back as 16 bit RGB565, two bytes per pixel, top row first.
    for ($y = 0; $y -lt $Height; $y++) {
        for ($x = 0; $x -lt $Width; $x++) {
            $i = (($y * $Width) + $x) * 2
            if ($i + 1 -ge $data.Length) { break }
            $pixel = [int]$data[$i] -bor ([int]$data[$i + 1] -shl 8)
            $r = ((($pixel -shr 11) -band 0x1F) * 255) / 31
            $g = ((($pixel -shr 5) -band 0x3F) * 255) / 63
            $b = (($pixel -band 0x1F) * 255) / 31
            $bitmap.SetPixel($x, $y, [Drawing.Color]::FromArgb([int]$r, [int]$g, [int]$b))
        }
    }
    $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    return $Path
}

function Get-LabKeyboard {
    param([Parameter(Mandatory)][string]$VMName)
    $objects = Get-LabVmObjects -VMName $VMName
    $keyboard = Get-CimAssociatedInstance -InputObject $objects.Vm -ResultClassName Msvm_Keyboard
    if (-not $keyboard) { throw 'No synthetic keyboard. Is the VM running?' }
    return $keyboard
}

function Send-LabText {
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Text)
    $keyboard = Get-LabKeyboard -VMName $VMName
    $result = Invoke-CimMethod -InputObject $keyboard -MethodName TypeText -Arguments @{ asciiText = $Text }
    if ($result.ReturnValue -ne 0) { throw "TypeText failed: $($result.ReturnValue)" }
}

function Send-LabKey {
    <# Virtual key codes: Enter 13, End 35, Down 40, Esc 27, Tab 9. #>
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][int]$KeyCode, [int]$Repeat = 1)
    $keyboard = Get-LabKeyboard -VMName $VMName
    for ($i = 0; $i -lt $Repeat; $i++) {
        $result = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = [uint32]$KeyCode }
        if ($result.ReturnValue -ne 0) { throw "TypeKey failed: $($result.ReturnValue)" }
        Start-Sleep -Milliseconds 60
    }
}

function Send-LabCtrlKey {
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][int]$KeyCode)
    $keyboard = Get-LabKeyboard -VMName $VMName
    [void](Invoke-CimMethod -InputObject $keyboard -MethodName PressKey   -Arguments @{ keyCode = [uint32]0x11 })
    [void](Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey    -Arguments @{ keyCode = [uint32]$KeyCode })
    [void](Invoke-CimMethod -InputObject $keyboard -MethodName ReleaseKey -Arguments @{ keyCode = [uint32]0x11 })
}
