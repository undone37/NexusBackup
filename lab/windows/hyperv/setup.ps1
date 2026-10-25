$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force C:\hv | Out-Null
Get-VM nx-rct -ErrorAction SilentlyContinue | ForEach-Object { Get-VMSnapshot -VM $_ | Remove-VMSnapshot; Remove-VM $_ -Force }
Remove-Item C:\hv\nx-rct*.vhdx, C:\hv\nx-rct*.avhdx, C:\hv\*.rct, C:\hv\*.mrt -ErrorAction SilentlyContinue
New-VHD -Path C:\hv\nx-rct.vhdx -SizeBytes 1GB -Dynamic | Out-Null
# 64 MiB of a known pattern at offset 0, written raw through the mounted disk
$d = Mount-VHD C:\hv\nx-rct.vhdx -NoDriveLetter -Passthru | Get-Disk
$f = [IO.File]::Open("\\.\PhysicalDrive$($d.Number)", "Open", "ReadWrite", "ReadWrite")
$buf = New-Object byte[] (1MB)
$rng = [System.Random]::new(42)
$sha = [Security.Cryptography.SHA256]::Create()
for ($i = 0; $i -lt 64; $i++) { $rng.NextBytes($buf); $f.Write($buf, 0, $buf.Length); [void]$sha.TransformBlock($buf, 0, $buf.Length, $null, 0) }
[void]$sha.TransformFinalBlock(@(), 0, 0); $f.Close()
Dismount-VHD C:\hv\nx-rct.vhdx
New-VM -Name nx-rct -Generation 2 -MemoryStartupBytes 512MB -VHDPath C:\hv\nx-rct.vhdx -Path C:\hv | Out-Null
Set-VMFirmware nx-rct -EnableSecureBoot Off
"vm version $((Get-VM nx-rct).Version), sha256 first 64 MiB: $(-join ($sha.Hash | ForEach-Object { $_.ToString('x2') }))"
