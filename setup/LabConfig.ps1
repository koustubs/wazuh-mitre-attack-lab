#requires -Version 5.1
<#
    One place the lab's names, addresses and sizes are written down, and one reader for it.

    Before this existed the subnet 172.29.70.x appeared in eight files, the switch name in four,
    the three VM names in seven and the guest account in six. Every one of them had to agree, and
    nothing enforced that they did. Changing the subnet meant finding all eight.

    Dot-source this from any script under the repository root:

        . (Join-Path $PSScriptRoot 'LabConfig.ps1')      # from setup\
        . (Join-Path $PSScriptRoot '..\setup\LabConfig.ps1')

    Nothing here writes, starts or changes anything. It reads lab.config.json and answers
    questions about it.
#>

Set-StrictMode -Version Latest

$script:LabConfigCache = $null
$script:LabRootCache = $null

function Get-LabRoot {
    <#
        The repository root, found by walking up until lab.config.json appears rather than by
        counting "..". Counting is how the old layout ended up with '..\..\..\05-detection-
        modelling\scorer' in the dashboard, which broke the moment anything moved.
    #>
    if ($script:LabRootCache) { return $script:LabRootCache }
    $dir = $PSScriptRoot
    while ($dir) {
        if (Test-Path -LiteralPath (Join-Path $dir 'lab.config.json')) {
            $script:LabRootCache = $dir
            return $dir
        }
        $parent = Split-Path -Parent $dir
        if ($parent -eq $dir) { break }
        $dir = $parent
    }
    throw 'lab.config.json was not found in any parent directory. Run this from inside the repository.'
}

function Get-LabConfig {
    <#
        .PARAMETER Profile
        Overrides the profile named in the file, for one call. Useful for "what would lean cost".
    #>
    param([ValidateSet('lean', 'full')][string]$Profile)

    if (-not $script:LabConfigCache) {
        $path = Join-Path (Get-LabRoot) 'lab.config.json'
        try {
            $script:LabConfigCache = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            throw "lab.config.json is not readable as JSON: $($_.Exception.Message)"
        }
    }
    $config = $script:LabConfigCache
    if ($Profile) { $config.profile = $Profile }

    if ($config.profile -notin @('lean', 'full')) {
        throw "Unknown profile '$($config.profile)'. Use lean or full."
    }
    if ($config.backend -notin @('hyperv', 'virtualbox')) {
        throw "Unknown backend '$($config.backend)'. Use hyperv or virtualbox."
    }
    return $config
}

function Get-LabVms {
    <#
        The VMs the active profile builds, with their resources already resolved, in the order
        they must start: manager first, so the agents have something to connect to.

        A VM absent from the profile is absent from this list. The lean profile has no Windows
        endpoint, and the dashboard must treat that as correct rather than as a missing VM.
    #>
    param(
        [ValidateSet('lean', 'full')][string]$Profile,
        # A subset of the profile's VMs, for rebuilding one machine without touching the others.
        # Validated against the profile, so a name the profile does not build is an error rather
        # than an empty result that quietly builds nothing.
        [string[]]$Only
    )

    $config = if ($Profile) { Get-LabConfig -Profile $Profile } else { Get-LabConfig }
    $active = $config.profile
    $result = [ordered]@{}

    foreach ($name in $config.profiles.$active.vms) {
        $vm = $config.vms.$name
        if (-not $vm) { throw "Profile '$active' names a VM that lab.config.json does not define: $name" }
        if (-not $vm.resources.PSObject.Properties.Name.Contains($active)) {
            throw "VM '$name' has no resources for profile '$active'."
        }
        $r = $vm.resources.$active
        $result[$name] = [ordered]@{
            Name        = $name
            Role        = $vm.role
            Hostname    = $vm.hostname
            # What the manager calls this endpoint in client.keys, which is not its hostname:
            # the Windows guest is WAZUH-WIN on the network and wazuh-windows to the manager.
            # Empty for the manager, which is not an agent.
            AgentName   = $(if ($vm.PSObject.Properties.Name -contains 'agentName') { [string]$vm.agentName } else { '' })
            Os          = $vm.os
            Address     = $vm.address
            Probes      = @($vm.probes)
            MemoryMb    = [int]$r.memoryMb
            MinMemoryMb = [int]$r.minMemoryMb
            MaxMemoryMb = [int]$r.maxMemoryMb
            Cpu         = [int]$r.cpu
            DiskGb      = [int]$r.diskGb
        }
    }

    if ($Only) {
        $unknown = @($Only | Where-Object { -not $result.Contains($_) })
        if ($unknown.Count -gt 0) {
            throw ("The {0} profile does not build: {1}. It builds {2}." -f
                $active, ($unknown -join ', '), ($result.Keys -join ', '))
        }
        # Walked in the profile's order rather than the order the names were given, because the
        # order this returns is a start order: the manager comes up before anything enrolling
        # against it, and -Only should not be able to invert that.
        $filtered = [ordered]@{}
        foreach ($name in $result.Keys) {
            if ($Only -contains $name) { $filtered[$name] = $result[$name] }
        }
        $result = $filtered
    }
    return $result
}

function Get-LabBudget {
    <#
        What the active profile costs, summed from the same numbers that build the VMs.

        The dashboard used to carry a hand-written "$labNeedsGb = 16" and the prose "16 GB" in two
        more places, all of which were the sum of New-Lab.ps1's spec table and all of which would
        have gone stale the moment that table changed.

        DiskGb is the sum of the virtual disk ceilings. Disks are dynamically expanding, so this
        is the worst case, not the day-one footprint. Checkpoints are the reason for the headroom
        on top.
    #>
    param(
        [ValidateSet('lean', 'full')][string]$Profile,
        [string[]]$Only
    )

    # Splatted rather than branched on both arguments, which is four spellings of one idea.
    $pass = @{}
    if ($Profile) { $pass['Profile'] = $Profile }
    if ($Only)    { $pass['Only']    = $Only }
    $vms = Get-LabVms @pass

    # Summed in a loop rather than with Measure-Object, because the entries are ordered
    # dictionaries and Measure-Object -Property only sees object properties, not hashtable keys.
    $memoryMb = 0; $maxMemoryMb = 0; $diskGb = 0; $cpu = 0
    foreach ($vm in $vms.Values) {
        $memoryMb    += $vm.MemoryMb
        $maxMemoryMb += $vm.MaxMemoryMb
        $diskGb      += $vm.DiskGb
        $cpu         += $vm.Cpu
    }
    [ordered]@{
        VmCount     = $vms.Count
        MemoryGb    = [math]::Round($memoryMb / 1024, 1)
        MaxMemoryGb = [math]::Round($maxMemoryMb / 1024, 1)
        Cpu         = $cpu
        DiskGb      = $diskGb
        # Room for the disks plus checkpoint differencing. A checkpoint of a VM that has been
        # running a while is not free, and running out of space mid-write corrupts the disk.
        DiskWithHeadroomGb = [int][math]::Ceiling($diskGb * 1.25)
    }
}

function Get-LabMacAddress {
    <#
        The MAC for the adapter carrying a guest's lab address, derived from the address itself.

        VirtualBox needs this. Its guests have two adapters, one for the internet and one for
        the lab, and neither netplan nor Get-NetAdapter has a way to say "the second one":
        interface names depend on PCI slot ordering the guest decides. Matching on a MAC the
        host chose is the only way to be certain which adapter gets the static address. Hyper-V
        guests have one adapter and do not need it, but they are given the same one anyway, so
        that a guest configuration file does not have to know which backend built it.

        080027 is Oracle's OUI, so the address stays inside the range VirtualBox itself uses.
        The last three bytes are the last three octets of the lab address, which makes it unique
        per guest and readable in a packet capture.

        .PARAMETER Separator
        Empty for VirtualBox, which takes twelve bare hex digits. ':' for netplan, '-' for
        Get-NetAdapter and Hyper-V.
    #>
    param(
        [Parameter(Mandatory)][string]$Address,
        [ValidateSet('', ':', '-')][string]$Separator = ''
    )
    $octets = $Address.Split('.')
    $bare = '080027{0:X2}{1:X2}{2:X2}' -f [int]$octets[1], [int]$octets[2], [int]$octets[3]
    if (-not $Separator) { return $bare }
    return (($bare -split '(..)' | Where-Object { $_ }) -join $Separator)
}

function Get-LabNullDevice {
    <#
        The platform's bit bucket. Written as the literal NUL in four places, which is correct on
        Windows and silently creates a file called NUL in the working directory anywhere else.
    #>
    if ($env:OS -eq 'Windows_NT') { 'NUL' } else { '/dev/null' }
}

function Get-LabSshOptions {
    <#
        The ssh options every host-side caller uses, in one place.

        There were four copies of this list and three of them agreed. Callers that cannot use
        the whole list, because they run inside a Start-Job runspace that cannot see this
        function, take the device name from Get-LabNullDevice instead.

        StrictHostKeyChecking is off and nothing is remembered on purpose: these guests are
        rebuilt often, so a changed host key is the expected case rather than a warning worth
        stopping for. That is a defensible trade inside a lab subnet reachable only from this
        host, and it would not be defensible anywhere else.
    #>
    param([Parameter(Mandatory)][string]$KeyPath, [int]$ConnectTimeout = 8)

    $nullDevice = Get-LabNullDevice
    @(
        '-i', $KeyPath
        '-o', 'BatchMode=yes'
        '-o', 'StrictHostKeyChecking=no'
        '-o', "UserKnownHostsFile=$nullDevice"
        '-o', "ConnectTimeout=$ConnectTimeout"
        # Without this, every call prints "Permanently added ... to the list of known hosts" on
        # stderr, because the known hosts file is the null device and nothing is ever remembered.
        '-o', 'LogLevel=ERROR'
    )
}

function Get-LabPath {
    <#
        Paths that more than one script needs, resolved from the root rather than from wherever
        the caller happens to be.
    #>
    param([Parameter(Mandatory)][ValidateSet('Secrets', 'Seeds', 'Evidence', 'Findings', 'Cache', 'Images', 'Scorer', 'Config')][string]$Name)

    $root = Get-LabRoot
    switch ($Name) {
        'Secrets'  { Join-Path $root '.lab-secrets' }
        'Seeds'    { Join-Path $root '.lab-secrets\seeds' }
        'Evidence' { Join-Path $root 'evidence' }
        'Findings' { Join-Path $root 'evidence\findings' }
        'Cache'    { Join-Path $root '.cache' }
        # Not under the repository. Preparing the cloud image needs room for the converted
        # disk as well as the result, and the finished image is the thing every guest's disk
        # is copied from. It belongs beside the VM disks, on the drive the profile was sized
        # against and the one the preflight checks.
        'Images'   { Join-Path ((Get-LabConfig).storageRoot -replace '/', '\') 'images' }
        'Scorer'   { Join-Path $root 'scoring\scorer' }
        'Config'   { Join-Path $root 'lab.config.json' }
    }
}
