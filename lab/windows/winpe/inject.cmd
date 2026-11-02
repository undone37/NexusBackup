@echo off
rem WinPE side of the #19 spike (case B): find the restored Windows volume and the virtio-win medium, add the
rem VirtIO storage and network drivers to the offline Windows with DISM, keep the log on the WinPE disk, shut down.
wpeinit
set LOG=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\nexus-winpe.txt set LOG=%%d:\inject.log
if "%LOG%"=="" set LOG=X:\inject.log
echo start %date% %time% > %LOG%
set WIN=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\Windows\System32\config\SYSTEM set WIN=%%d:
set CD=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\vioscsi\2k22\amd64\vioscsi.inf set CD=%%d:
echo windows=%WIN% virtio=%CD% >> %LOG%
diskpart /s X:\list.txt >> %LOG% 2>&1
if "%WIN%"=="" goto end
if "%CD%"=="" goto end
dism /Image:%WIN%\ /Add-Driver /Driver:%CD%\vioscsi\2k22\amd64 /Driver:%CD%\viostor\2k22\amd64 /Driver:%CD%\NetKVM\2k22\amd64 >> %LOG% 2>&1
echo dism=%errorlevel% >> %LOG%
dism /Image:%WIN%\ /Get-Drivers >> %LOG% 2>&1
:end
echo end %date% %time% >> %LOG%
wpeutil shutdown
