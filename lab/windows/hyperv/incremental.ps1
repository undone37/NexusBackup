$ErrorActionPreference = "Stop"
$ns = "root\virtualization\v2"
function Wait-Job($r, $what) {
  if ($r.ReturnValue -eq 4096) { $j = [wmi]$r.Job; while ($j.JobState -lt 7) { Start-Sleep -Milliseconds 300; $j = [wmi]$r.Job }
    if ($j.JobState -ne 7) { throw "$what failed: $($j.ErrorDescription)" } } elseif ($r.ReturnValue -ne 0) { throw "$what returned $($r.ReturnValue)" }
}
$svc = gwmi -Namespace $ns Msvm_VirtualSystemSnapshotService
$ims = gwmi -Namespace $ns Msvm_ImageManagementService
$vmid = (Get-VM nx-rct).Id.ToString().ToUpper()
$rp = @(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid })[0]
$id = $rp.ResilientChangeTrackingIdentifiers[0]
"base reference point: $id"
& C:\hv\keys.ps1 "yes NEXUSRCT3 | head -c 4194304 | dd of=/dev/sda bs=1M seek=128 oflag=direct iflag=fullblock"
Start-Sleep 12
$vm = gwmi -Namespace $ns Msvm_ComputerSystem -Filter "ElementName='nx-rct'"
$ssd = ([wmiclass]"\\.\${ns}:Msvm_VirtualSystemSnapshotSettingData").CreateInstance(); $ssd.ConsistencyLevel = 2; $ssd.IgnoreNonSnapshottableDisks = $true
Wait-Job ($svc.CreateSnapshot($vm, $ssd.GetText(2), 32768)) "CreateSnapshot"
"checkpoint: VM on $((Get-VMHardDiskDrive nx-rct).Path)"
& C:\hv\qcvd.ps1 C:\hv\nx-rct.vhdx $id 1
$in = $ims.GetMethodParameters("GetVirtualDiskChanges")
$in.Path = "C:\hv\nx-rct.vhdx"; $in.TargetSnapshotId = $id; $in.ByteOffset = [uint64]0; $in.ByteLength = [uint64]1GB
try { $r = $ims.InvokeMethod("GetVirtualDiskChanges", $in, $null); Wait-Job $r "GetVirtualDiskChanges"
  "WMI changes: " + ((0..(@($r.ChangedByteOffsets).Count - 1) | Where-Object { $r.ChangedByteOffsets } | ForEach-Object { "$($r.ChangedByteOffsets[$_])+$($r.ChangedByteLengths[$_])" }) -join ' ')
} catch { "WMI: $($_.Exception.Message.Split([char]10)[-1])" }
$snap = gwmi -Namespace $ns Msvm_VirtualSystemSettingData -Filter "VirtualSystemIdentifier='$vmid' AND VirtualSystemType='Microsoft:Hyper-V:Snapshot:Recovery'" | Select-Object -Last 1
$cin = $svc.GetMethodParameters("ConvertToReferencePoint"); $cin.AffectedSnapshot = $snap.__PATH
Wait-Job ($svc.InvokeMethod("ConvertToReferencePoint", $cin, $null)) "ConvertToReferencePoint"
"converted; reference points of the VM: $(@(gwmi -Namespace $ns Msvm_VirtualSystemReferencePoint | Where-Object { $_.VirtualSystemIdentifier -eq $vmid } | ForEach-Object { $_.ResilientChangeTrackingIdentifiers[0] }) -join ', ')"
