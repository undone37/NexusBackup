param([string]$path, [string]$rctId)
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class Vd {
  [StructLayout(LayoutKind.Sequential)] public struct VST { public uint DeviceId; public Guid VendorId; }
  [StructLayout(LayoutKind.Sequential)] public struct OpenV2 { public uint Version; public int GetInfoOnly; public int ReadOnly; public Guid ResiliencyGuid; }
  [StructLayout(LayoutKind.Sequential)] public struct Range { public ulong ByteOffset; public ulong ByteLength; public ulong Reserved; }
  [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)] public static extern int OpenVirtualDisk(ref VST t, string path, uint access, uint flags, ref OpenV2 p, out IntPtr h);
  [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)] public static extern int QueryChangesVirtualDisk(IntPtr h, string id, ulong off, ulong len, uint flags, [Out] Range[] ranges, ref uint count, out ulong processed);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
$t = New-Object Vd+VST; $t.DeviceId = 3; $t.VendorId = [Guid]"EC984AEC-A0F9-47e9-901F-71415A66345B"  # VHDX, Microsoft
$p = New-Object Vd+OpenV2; $p.Version = 2; $p.GetInfoOnly = 1
$h = [IntPtr]::Zero
$rc = [Vd]::OpenVirtualDisk([ref]$t, $path, 0, 0, [ref]$p, [ref]$h)   # VIRTUAL_DISK_ACCESS_NONE with v2 params
"OpenVirtualDisk $path -> $rc"
if ($rc -ne 0) { return }
$ranges = New-Object Vd+Range[] 1024; $n = [uint32]1024; $done = [uint64]0
$rc = [Vd]::QueryChangesVirtualDisk($h, $rctId, 0, 1GB, 0, $ranges, [ref]$n, [ref]$done)
"QueryChangesVirtualDisk since $rctId -> $rc, $n ranges, processed ${done}: " + (($ranges[0..([Math]::Max([int]$n, 1) - 1)] | Where-Object { $n } | ForEach-Object { "$($_.ByteOffset)+$($_.ByteLength)" }) -join ' ')
[void][Vd]::CloseHandle($h)
