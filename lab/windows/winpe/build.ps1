$ErrorActionPreference = 'Stop'
$kit = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit'
$env:PATH = "$kit\Deployment Tools\amd64\DISM;$kit\Deployment Tools\amd64\Oscdimg;$kit\Windows Preinstallation Environment;$env:PATH"
$cd = (Get-Volume | Where-Object { Test-Path "$($_.DriveLetter):\vioscsi\2k22\amd64\vioscsi.inf" } | Select-Object -First 1).DriveLetter
if (-not $cd) { throw 'virtio-win medium not found' }
if (Test-Path C:\WinPE) { Remove-Item -Recurse -Force C:\WinPE }
$env:WinPERoot = "$kit\Windows Preinstallation Environment"
$env:OSCDImgRoot = "$kit\Deployment Tools\amd64\Oscdimg"
cmd /c "`"$kit\Windows Preinstallation Environment\copype.cmd`" amd64 C:\WinPE" | Out-File C:\winpe-build.log
dism /Mount-Image /ImageFile:C:\WinPE\media\sources\boot.wim /Index:1 /MountDir:C:\WinPE\mount | Out-File -Append C:\winpe-build.log
dism /Image:C:\WinPE\mount /Add-Driver "/Driver:${cd}:\vioscsi\2k22\amd64" "/Driver:${cd}:\viostor\2k22\amd64" "/Driver:${cd}:\NetKVM\2k22\amd64" | Out-File -Append C:\winpe-build.log
Copy-Item C:\nx\inject.cmd C:\WinPE\mount\Windows\System32\startnet.cmd -Force
Copy-Item C:\nx\list.txt C:\WinPE\mount\list.txt -Force
dism /Unmount-Image /MountDir:C:\WinPE\mount /Commit | Out-File -Append C:\winpe-build.log
# the extra 2 GB disk: one active FAT32 partition, then the WinPE files on it
$d = Get-Disk | Where-Object { $_.Size -lt 3GB -and $_.Number -ne 0 } | Select-Object -First 1
if (-not $d) { throw 'no 2 GB disk' }
if ($d.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $d.Number -PartitionStyle MBR }
Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue | Remove-Partition -Confirm:$false
$p = New-Partition -DiskNumber $d.Number -UseMaximumSize -IsActive -DriveLetter P
Format-Volume -DriveLetter P -FileSystem FAT32 -NewFileSystemLabel WINPE -Confirm:$false | Out-Null
cmd /c "echo y| `"$kit\Windows Preinstallation Environment\MakeWinPEMedia.cmd`" /UFD /F C:\WinPE P:" | Out-File -Append C:\winpe-build.log
Set-Content P:\nexus-winpe.txt 'nexus winpe spike'
"ok $((Get-ChildItem P:\ -Recurse | Measure-Object Length -Sum).Sum) bytes on P:"
