# WinPE driver injection spike (#19, docs/bmr.md "Windows: recovery media spike", case B)

Our scripts only: the ADK, the WinPE add-on and the VirtIO drivers come from their vendors at run time and are never
committed (the maintainer accepted the ADK licence for the lab, 2026-11-01).

- `build.ps1` (on a Windows build VM with the ADK Deployment Tools and the WinPE add-on installed, the virtio-win
  ISO attached, an empty 2 GB disk): `copype amd64`, the VirtIO storage and network drivers added to `boot.wim`,
  `inject.cmd` as `startnet.cmd`, the media on the 2 GB disk (one active FAT32 partition). `MakeWinPEMedia /UFD`
  refused to set the boot code on a fixed disk: `bootsect /nt60 P: /force /mbr` and a `robocopy` of `media\` do it.
- `inject.cmd` (WinPE): finds the offline Windows (`\Windows\System32\config\SYSTEM`) and the virtio-win medium,
  `dism /Image:<win> /Add-Driver` for vioscsi, viostor and NetKVM, logs to the WinPE disk, shuts down.
- `list.txt`: the diskpart listing for the log.
