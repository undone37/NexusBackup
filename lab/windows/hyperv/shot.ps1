$ns = "root\virtualization\v2"
$vmid = (Get-VM nx-rct).Id.ToString().ToUpper()
$vssd = gwmi -Namespace $ns Msvm_VirtualSystemSettingData -Filter "VirtualSystemIdentifier='$vmid' AND VirtualSystemType='Microsoft:Hyper-V:System:Realized'"
$mgmt = gwmi -Namespace $ns Msvm_VirtualSystemManagementService
$r = $mgmt.GetVirtualSystemThumbnailImage($vssd, 640, 480)
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 640, 480, ([System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
$rect = New-Object System.Drawing.Rectangle 0, 0, 640, 480
$bd = $bmp.LockBits($rect, "WriteOnly", $bmp.PixelFormat)
[Runtime.InteropServices.Marshal]::Copy([byte[]]$r.ImageData, 0, $bd.Scan0, [Math]::Min($r.ImageData.Length, $bd.Stride * 480))
$bmp.UnlockBits($bd)
$ms = New-Object IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
"PNG:" + [Convert]::ToBase64String($ms.ToArray())
