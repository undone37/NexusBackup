$ErrorActionPreference = "Stop"
$ns = "root\virtualization\v2"
function Wait-Job($r, $what) {
  if ($r.ReturnValue -eq 4096) {
    $j = [wmi]$r.Job
    while ($j.JobState -lt 7) { Start-Sleep -Milliseconds 300; $j = [wmi]$r.Job }
    if ($j.JobState -ne 7) { throw "$what failed: $($j.ErrorDescription)" }
  } elseif ($r.ReturnValue -ne 0) { throw "$what returned $($r.ReturnValue)" }
}
$svc = gwmi -Namespace $ns Msvm_VirtualSystemSnapshotService
$rps = gwmi -Namespace $ns Msvm_VirtualSystemReferencePointService
$ims = gwmi -Namespace $ns Msvm_ImageManagementService
$vmid = (Get-VM nx-rct).Id.ToString().ToUpper()
function Vm { gwmi -Namespace $ns Msvm_ComputerSystem -Filter "ElementName='nx-rct'" }
function Checkpoint {
  $ssd = ([wmiclass]"\\.\${ns}:Msvm_VirtualSystemSnapshotSettingData").CreateInstance()
  $ssd.ConsistencyLevel = 2; $ssd.IgnoreNonSnapshottableDisks = $true
  Wait-Job ($svc.CreateSnapshot((Vm), $ssd.GetText(2), 32768)) "CreateSnapshot"
  gwmi -Namespace $ns Msvm_VirtualSystemSettingData -Filter "VirtualSystemIdentifier='$vmid' AND VirtualSystemType='Microsoft:Hyper-V:Snapshot:Recovery'" |
    Sort-Object CreationTime | Select-Object -Last 1
}
function RefPoint($snap) {
  $in = $svc.GetMethodParameters("ConvertToReferencePoint"); $in.AffectedSnapshot = $snap.__PATH
  Wait-Job ($svc.InvokeMethod("ConvertToReferencePoint", $in, $null)) "ConvertToReferencePoint"
  gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid } |
    Sort-Object CreationTime | Select-Object -Last 1
}
function Keys($text) { & C:\hv\keys.ps1 $text }
Get-VMSnapshot nx-rct | Remove-VMSnapshot
gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid } |
  ForEach-Object { Wait-Job ($rps.DestroyReferencePoint($_)) "DestroyReferencePoint" }
# the VM runs the Alpine live system, root logged in (hv-keys.ps1)
$before = @(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid } | ForEach-Object { $_.InstanceID })
[void](RefPoint (Checkpoint))
$rp1 = @(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid -and $before -notcontains $_.InstanceID })[0]
$id1 = $rp1.ResilientChangeTrackingIdentifiers[0]
"RP1: $id1 ($($rp1.InstanceID))"
Keys "yes NEXUSRCT | head -c 4194304 | dd of=/dev/sda bs=1M seek=512 oflag=direct iflag=fullblock"
Start-Sleep 15
$cp2 = Checkpoint
"VM now on: $((Get-VMHardDiskDrive nx-rct).Path)"
foreach ($path in @("C:\hv\nx-rct.vhdx", (Get-VMHardDiskDrive nx-rct).Path)) {
  $in = $ims.GetMethodParameters("GetVirtualDiskChanges")
  $in.Path = $path; $in.TargetSnapshotId = $id1; $in.ByteOffset = [uint64]0; $in.ByteLength = [uint64]1GB
  $t0 = Get-Date
  try {
    $r = $ims.InvokeMethod("GetVirtualDiskChanges", $in, $null); Wait-Job $r "GetVirtualDiskChanges"
    $o = @($r.ChangedByteOffsets | Where-Object { $_ -ne $null }); $l = @($r.ChangedByteLengths | Where-Object { $_ -ne $null })
    "changes since $id1 in $path ($([int]((Get-Date) - $t0).TotalMilliseconds) ms): $($o.Count): " + ((0..($o.Count - 1) | Where-Object { $o.Count } | ForEach-Object { "$($o[$_])+$($l[$_])" }) -join ' ')
  } catch { "changes in ${path}: $($_.Exception.Message)" }
}
$before = @(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid } | ForEach-Object { $_.InstanceID })
[void](RefPoint $cp2)
$rp2 = @(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid -and $before -notcontains $_.InstanceID })[0]
"RP2: $($rp2.ResilientChangeTrackingIdentifiers -join ',')"
Wait-Job ($rps.DestroyReferencePoint($rp1)) "DestroyReferencePoint"
"reference points of the VM left: $(@(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid }).Count)"
