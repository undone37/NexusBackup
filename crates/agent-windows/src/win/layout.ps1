# #19 (docs/bmr.md "Windows"): the disks, partitions and volumes for the machine layout, as JSON on the last line
# (crate::winlayout::Facts). Read only.
$ErrorActionPreference = 'Stop'
$disks = foreach ($d in Get-Disk) {
    $parts = foreach ($p in @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue)) {
        $v = $null
        try { $v = $p | Get-Volume -ErrorAction Stop } catch {}
        [ordered]@{
            number = [int]$p.PartitionNumber; offset = [uint64]$p.Offset; size = [uint64]$p.Size
            mbr_type = $p.MbrType; gpt_type = $p.GptType; guid = $p.Guid; active = [bool]$p.IsActive
            letter = [string]$p.DriveLetter; type = [string]$p.Type
            fs = $(if ($v) { [string]$v.FileSystem } else { $null })
            label = $(if ($v) { [string]$v.FileSystemLabel } else { $null })
            volume = $(if ($v) { [string]$v.Path } else { $null })
        }
    }
    [ordered]@{
        number = [int]$d.Number; size = [uint64]$d.Size; sector = [int]$d.LogicalSectorSize; model = [string]$d.FriendlyName
        style = [string]$d.PartitionStyle; signature = $d.Signature; guid = $d.Guid; boot = [bool]$d.IsBoot
        system = [bool]$d.IsSystem; bus = [string]$d.BusType; partitions = @($parts)
    }
}
$fw = (Get-ItemProperty HKLM:\System\CurrentControlSet\Control -Name PEFirmwareType -ErrorAction SilentlyContinue).PEFirmwareType
$os = Get-CimInstance Win32_OperatingSystem
[ordered]@{
    hostname = $env:COMPUTERNAME; firmware = $(if ($fw -eq 2) { 'uefi' } else { 'bios' })
    os = [string]$os.Caption; version = [string]$os.Version; disks = @($disks)
} | ConvertTo-Json -Compress -Depth 6
