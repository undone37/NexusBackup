# Hyper-V host backups of the Windows agent (#39, docs/hyperv-design.md M1), run by win/hyperv.rs through
# powershell.exe -EncodedCommand. Input: $env:NEXUS_HV = {"action": "list" | "prepare" | "finish", ...}. Output: one
# line of JSON on stdout; a failure throws (exit code 1, the message on stderr).
#   list                          [{id, name, state, generation, disks: [{name, path}]}]
#   prepare {vm}                  recovery checkpoint (application consistent, else crash consistent), the frozen
#                                 parent of each disk mounted read-only: {vm, name, consistency, checkpoint, config,
#                                 disks: [{name, target, size, file, device}]}
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
        $disk = Mount-VHD -Path $parent -ReadOnly -NoDriveLetter -Passthru | Get-Disk
        $disks += [ordered]@{ name = (DiskName $d); target = $n; size = $size; file = $parent; device = "\\.\PhysicalDrive$($disk.Number)" }
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
  default { throw "unknown action $($a.action)" }
}
