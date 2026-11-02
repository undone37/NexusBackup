# Hyper-V host backups of the Windows agent (#39, docs/hyperv-design.md M1), run by win/hyperv.rs through
# powershell.exe -EncodedCommand. Input: $env:NEXUS_HV = {"action": "list" | "prepare" | "finish", ...}. Output: one
# line of JSON on stdout; a failure throws (exit code 1, the message on stderr).
#   list                          [{id, name, state, generation, disks: [{name, path}]}]
#   prepare {vm, rct}             recovery checkpoint (application consistent, else crash consistent), the frozen
#                                 parent of each disk mounted read-only: {vm, name, consistency, checkpoint, config,
#                                 disks: [{name, target, size, file, device, changed}]}; with `rct` (the previous
#                                 reference point's ids, one per disk in order, #39 M2) `changed` lists the byte
#                                 ranges written since (virtdisk QueryChangesVirtualDisk on the frozen parent, as in
#                                 the lab), null when there is no valid base for the disk (then it is read in full)
#   finish {prepared, keep}       disks dismounted; keep: the checkpoint becomes a reference point: {reference_point,
#                                 rct}; else the checkpoint is removed: {}
# The WMI sequence is the one of the lab (lab/windows/hyperv/rct.ps1): asynchronous jobs leave the out references
# empty, so new instances are found by comparing instance ids; methods are called with named parameters.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$a = $env:NEXUS_HV | ConvertFrom-Json
$ns = 'root\virtualization\v2'

function Wait-Wmi($r, $what) {
  if ($r.ReturnValue -eq 4096) {
    $j = [wmi]$r.Job
    while ($j.JobState -lt 7) { Start-Sleep -Milliseconds 300; $j = [wmi]$r.Job }
    if ($j.JobState -ne 7) { throw "${what}: $($j.ErrorDescription)" }
  } elseif ($r.ReturnValue -ne 0) { throw "$what returned $($r.ReturnValue)" }
}
function Recovery($id) {
  @(Get-WmiObject -Namespace $ns Msvm_VirtualSystemSettingData -Filter "VirtualSystemType='Microsoft:Hyper-V:Snapshot:Recovery'" |
    Where-Object { $_.VirtualSystemIdentifier -eq $id })
}
function RefPoints($id) {
  @(Get-WmiObject -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $id })
}
function DiskName($d) { ("$($d.ControllerType)$($d.ControllerNumber)-$($d.ControllerLocation)").ToLower() }
function Out($o) { ConvertTo-Json -InputObject $o -Depth 6 -Compress }
# RCT change query (#39 M2): open the frozen parent VHDX read-only with virtdisk.dll and page through
# QueryChangesVirtualDisk; null when the id is not valid for the disk (reset, changed outside Hyper-V) or too many ranges
function Changes($path, $id, $size) {
  if (-not ('NxVd' -as [type])) {
    Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class NxVd {
  [StructLayout(LayoutKind.Sequential)] public struct VST { public uint DeviceId; public Guid VendorId; }
  [StructLayout(LayoutKind.Sequential)] public struct OpenV2 { public uint Version; public int GetInfoOnly; public int ReadOnly; public Guid ResiliencyGuid; }
  [StructLayout(LayoutKind.Sequential)] public struct Range { public ulong ByteOffset; public ulong ByteLength; public ulong Reserved; }
  [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)] public static extern int OpenVirtualDisk(ref VST t, string path, uint access, uint flags, ref OpenV2 p, out IntPtr h);
  [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)] public static extern int QueryChangesVirtualDisk(IntPtr h, string id, ulong off, ulong len, uint flags, [Out] Range[] ranges, ref uint count, out ulong processed);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
  }
  if (-not $id -or $id -notmatch '^[A-Za-z0-9:-]{1,200}$') { return $null }
  $t = New-Object NxVd+VST; $t.DeviceId = 3; $t.VendorId = [Guid]'EC984AEC-A0F9-47e9-901F-71415A66345B'
  $p = New-Object NxVd+OpenV2; $p.Version = 2; $p.ReadOnly = 1
  $h = [IntPtr]::Zero
  if ([NxVd]::OpenVirtualDisk([ref]$t, $path, 0, 0, [ref]$p, [ref]$h) -ne 0) { return $null }
  try {
    $out = New-Object System.Collections.Generic.List[object]
    $off = [uint64]0
    while ($off -lt [uint64]$size) {
      $buf = New-Object NxVd+Range[] 4096; $n = [uint32]4096; $done = [uint64]0
      if ([NxVd]::QueryChangesVirtualDisk($h, $id, $off, [uint64]$size - $off, 0, $buf, [ref]$n, [ref]$done) -ne 0) { return $null }
      for ($i = 0; $i -lt $n; $i++) { $out.Add(@([uint64]$buf[$i].ByteOffset, [uint64]$buf[$i].ByteLength)) }
      if ($out.Count -gt 8192) { return $null }   # the answer stays small; a disk changed this much is read in full
      if ($done -eq 0) { break }
      $off += $done
    }
    return ,$out.ToArray()
  } finally { [void][NxVd]::CloseHandle($h) }
}

switch ($a.action) {
  'list' {
    $vms = foreach ($vm in @(Get-VM)) {
      [ordered]@{
        id = $vm.Id.ToString().ToUpper(); name = $vm.Name; state = "$($vm.State)"; generation = $vm.Generation
        disks = @(Get-VMHardDiskDrive -VM $vm | ForEach-Object { [ordered]@{ name = (DiskName $_); path = $_.Path } })
      }
    }
    Out @($vms)
  }
  'prepare' {
    $id = $a.vm.ToUpper()
    $vm = Get-VM -Id $id
    $wvm = Get-WmiObject -Namespace $ns Msvm_ComputerSystem -Filter "Name='$id'"
    $svc = Get-WmiObject -Namespace $ns Msvm_VirtualSystemSnapshotService
    $before = @(Recovery $id | ForEach-Object { $_.InstanceID })
    $consistency = 'application'
    try {
      $ssd = ([wmiclass]"\\.\${ns}:Msvm_VirtualSystemSnapshotSettingData").CreateInstance()
      $ssd.ConsistencyLevel = 1; $ssd.IgnoreNonSnapshottableDisks = $true
      Wait-Wmi ($svc.CreateSnapshot($wvm, $ssd.GetText(2), 32768)) 'CreateSnapshot'
    } catch {
      # no integration services (or VSS in the guest failed): crash consistent, as a power cut would leave it
      $consistency = 'crash'
      $ssd.ConsistencyLevel = 2
      Wait-Wmi ($svc.CreateSnapshot($wvm, $ssd.GetText(2), 32768)) 'CreateSnapshot'
    }
    $snap = @(Recovery $id | Where-Object { $before -notcontains $_.InstanceID })[0]
    if (-not $snap) { throw 'the recovery checkpoint was created but not found' }
    $disks = @()
    try {
      $n = 0
      foreach ($d in @(Get-VMHardDiskDrive -VM $vm)) {
        if (-not $d.Path) { continue }
        $parent = (Get-VHD -Path $d.Path).ParentPath
        if (-not $parent) { continue } # not covered by the checkpoint (pass-through, excluded)
        $n++
        $size = (Get-VHD -Path $parent).Size
        $changed = $null
        if ($a.rct -and @($a.rct).Count -ge $n) { $changed = Changes $parent @($a.rct)[$n - 1] $size }
        $disk = Mount-VHD -Path $parent -ReadOnly -NoDriveLetter -Passthru | Get-Disk
        $disks += [ordered]@{ name = (DiskName $d); target = $n; size = $size; file = $parent; device = "\\.\PhysicalDrive$($disk.Number)"; changed = $changed }
      }
    } catch {
      foreach ($d in $disks) { Dismount-VHD -Path $d.file -ErrorAction SilentlyContinue }
      Wait-Wmi ($svc.DestroySnapshot($snap)) 'DestroySnapshot'
      throw
    }
    $fw = $null
    if ($vm.Generation -eq 2) { $f = Get-VMFirmware -VM $vm; $fw = [ordered]@{ secure_boot = "$($f.SecureBoot)"; template = $f.SecureBootTemplate } }
    $config = [ordered]@{
      name = $vm.Name; generation = $vm.Generation; version = $vm.Version; cpus = $vm.ProcessorCount
      memory_mb = [int64]($vm.MemoryStartup / 1MB); dynamic_memory = $vm.DynamicMemoryEnabled; firmware = $fw
      nics = @(Get-VMNetworkAdapter -VM $vm | ForEach-Object { [ordered]@{ name = $_.Name; switch = $_.SwitchName; mac = $_.MacAddress } })
    }
    Out ([ordered]@{ vm = $id; name = $vm.Name; consistency = $consistency; checkpoint = $snap.InstanceID; config = $config; disks = $disks })
  }
  'finish' {
    $p = $a.prepared
    $id = $p.vm
    foreach ($d in @($p.disks)) { Dismount-VHD -Path $d.file -ErrorAction SilentlyContinue }
    $svc = Get-WmiObject -Namespace $ns Msvm_VirtualSystemSnapshotService
    $snap = @(Recovery $id | Where-Object { $_.InstanceID -eq $p.checkpoint })[0]
    if (-not $snap) { throw "checkpoint $($p.checkpoint) of VM $id not found" }
    if (-not $a.keep) {
      Wait-Wmi ($svc.DestroySnapshot($snap)) 'DestroySnapshot'
      Out @{}
      break
    }
    $before = @(RefPoints $id | ForEach-Object { $_.InstanceID })
    $in = $svc.GetMethodParameters('ConvertToReferencePoint'); $in.AffectedSnapshot = $snap.__PATH
    Wait-Wmi ($svc.InvokeMethod('ConvertToReferencePoint', $in, $null)) 'ConvertToReferencePoint'
    $rp = @(RefPoints $id | Where-Object { $before -notcontains $_.InstanceID })[0]
    if (-not $rp) { throw 'the reference point was created but not found' }
    # ponytail: earlier reference points stay (metadata only); M2 destroys the one it used as its base, never those
    # of other backup tools
    Out ([ordered]@{ reference_point = $rp.InstanceID; rct = @($rp.ResilientChangeTrackingIdentifiers) })
  }
  'restore_begin' {
    # #39 M4: the disks of a new VM as dynamic VHDX files below the host's virtual disk path, in a directory named
    # after the VM (refused if it exists), mounted and offline (no volume gets mounted while raw blocks arrive)
    $sp = $a.spec
    $name = [string]$sp.name
    if ($name -notmatch '^[^\\/:*?"<>|\x00-\x1f]{1,100}$') { throw "invalid VM name" }
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw "a VM named $name exists" }
    $dir = Join-Path (Get-VMHost).VirtualHardDiskPath $name
    if (Test-Path $dir) { throw "$dir exists" }
    New-Item -ItemType Directory -Path $dir | Out-Null
    $disks = @()
    try {
      $n = 0
      foreach ($d in @($sp.disks)) {
        $n++
        if ([string]$d.name -notmatch '^[A-Za-z0-9-]{1,32}$') { throw "invalid disk name" }
        $file = Join-Path $dir "$($d.name).vhdx"
        New-VHD -Path $file -SizeBytes ([uint64]$d.size) -Dynamic | Out-Null
        $disk = Mount-VHD -Path $file -Passthru | Get-Disk
        Set-Disk -Number $disk.Number -IsOffline $true -ErrorAction SilentlyContinue
        Set-Disk -Number $disk.Number -IsReadOnly $false
        $disks += [ordered]@{ name = [string]$d.name; target = $n; file = $file; device = "\\.\PhysicalDrive$($disk.Number)" }
      }
    } catch {
      foreach ($d in $disks) { Dismount-VHD -Path $d.file -ErrorAction SilentlyContinue }
      Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
      throw
    }
    Out ([ordered]@{ name = $name; dir = $dir; config = $sp.config; disks = $disks })
  }
  'restore_finish' {
    # the disks closed; keep: the VM defined from the snapshot's settings (powered off, NICs not connected, new
    # MACs: the original may still run), else the files removed
    $b = $a.begun
    foreach ($d in @($b.disks)) { Dismount-VHD -Path $d.file -ErrorAction SilentlyContinue }
    if (-not $a.keep) {
      Remove-Item -Recurse -Force $b.dir -ErrorAction SilentlyContinue
      Out @{}
      break
    }
    $c = $b.config
    $gen = if ($c.generation -eq 1) { 1 } else { 2 }
    $mem = [int64]($(if ($c.memory_mb) { $c.memory_mb } else { 1024 })) * 1MB
    $vm = New-VM -Name $b.name -Generation $gen -MemoryStartupBytes $mem -NoVHD -Path $b.dir
    if ($c.cpus) { Set-VMProcessor -VM $vm -Count ([int]$c.cpus) }
    $i = 0
    foreach ($d in @($b.disks)) {
      if ($gen -eq 1 -and $i -lt 2) { Add-VMHardDiskDrive -VM $vm -ControllerType IDE -ControllerNumber 0 -ControllerLocation $i -Path $d.file }
      else { Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $d.file }
      $i++
    }
    if ($gen -eq 2) {
      $sb = if ($c.firmware.secure_boot -eq 'On') { 'On' } else { 'Off' }
      Set-VMFirmware -VM $vm -EnableSecureBoot $sb -FirstBootDevice (Get-VMHardDiskDrive -VM $vm | Select-Object -First 1)
      if ($sb -eq 'On' -and $c.firmware.template) { Set-VMFirmware -VM $vm -SecureBootTemplate $c.firmware.template }
    }
    $nics = @($c.nics).Count
    for ($k = 1; $k -lt $nics; $k++) { Add-VMNetworkAdapter -VM $vm }
    Out ([ordered]@{ vm = $vm.Id.ToString().ToUpper(); name = $vm.Name })
  }
  default { throw "unknown action $($a.action)" }
}
