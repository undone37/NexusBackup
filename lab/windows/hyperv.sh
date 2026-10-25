#!/usr/bin/env bash
# Hyper-V facts for the design note (#39, docs/hyperv-design.md): a clone of the lab Windows Server 2022 (VM 242)
# with the Hyper-V role (nested virtualization, CPU type host), a test VM, recovery checkpoints, reference points
# and RCT through WMI. Driven through the guest agent (gexec.py); the PowerShell steps are in lab/windows/hyperv/.
#
#   hyperv.sh host    VM $VMID: full clone of VM 242, 8 GB, renamed nx-hyperv, Hyper-V role, restarted
#   hyperv.sh vm      test VM nx-rct (Gen 2, 1 GiB VHDX, the first 64 MiB a known pattern; setup.ps1), the Alpine
#                     virt ISO as its DVD (keys.ps1 logs in: TypeText does not reach a Linux guest, TypeKey does)
#   hyperv.sh rct     recovery checkpoint -> reference point, 4 MiB written in the guest, checkpoint, change query,
#                     the base disk read while the VM runs (rct.ps1)
#   hyperv.sh shot    the test VM's screen (WMI thumbnail) -> $OUT/nx-rct.png
#
# env: VMID (296), ALPINE (the virt ISO URL), OUT (~/nexus-lab/scratch/hv)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
VMID=${VMID:-296}
ALPINE=${ALPINE:-https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-virt-3.22.2-x86_64.iso}
OUT=${OUT:-$HOME/nexus-lab/scratch/hv}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
[ "$VMID" -ge 200 ] || { echo "VMID $VMID: only VMs from 200 are ours" >&2; exit 1; }
mkdir -p "$OUT"
win() { "$here/gexec.py" "$VMID" "$1"; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@"; }
wait_agent() { for _ in $(seq 1 90); do win 'exit 0' >/dev/null 2>&1 && return; sleep 10; done; echo "no guest agent" >&2; exit 1; }
put() { for f in "$@"; do "$here/gexec.py" "$VMID" --put "$here/hyperv/$f" "C:\\hv\\$f" >/dev/null; done; }

case ${1:?step} in
host)
	pve "qm status $VMID >/dev/null 2>&1 || { qm clone 242 $VMID --name nx-hyperv --full >/dev/null &&
		qm set $VMID --memory 8192 --cores 4 --cpu host >/dev/null; }; qm start $VMID 2>/dev/null || true"
	wait_agent
	win 'Rename-Computer -NewName nx-hyperv -Force -WarningAction SilentlyContinue
		(Install-WindowsFeature Hyper-V -IncludeManagementTools).ExitCode; shutdown /r /t 5 | Out-Null'
	sleep 90
	wait_agent
	win '"$env:COMPUTERNAME: Hyper-V $((Get-WindowsFeature Hyper-V).InstallState)"'
	;;
vm)
	win 'New-Item -ItemType Directory -Force C:\hv | Out-Null'
	put setup.ps1 keys.ps1 shot.ps1 rct.ps1
	win "if (-not (Test-Path C:\\hv\\alpine.iso)) { \$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest '$ALPINE' -OutFile C:\\hv\\alpine.iso -UseBasicParsing }
		& C:\\hv\\setup.ps1
		Add-VMDvdDrive nx-rct -Path C:\\hv\\alpine.iso; Set-VMFirmware nx-rct -FirstBootDevice (Get-VMDvdDrive nx-rct)
		Start-VM nx-rct; Start-Sleep 60; & C:\\hv\\keys.ps1 root; 'nx-rct running Alpine, root logged in'"
	;;
rct)
	put rct.ps1 keys.ps1
	win '& C:\hv\rct.ps1'
	;;
shot)
	put shot.ps1
	win '& C:\hv\shot.ps1' | sed -n 's/^PNG://p' | base64 -d >"$OUT/nx-rct.png"
	echo "$OUT/nx-rct.png"
	;;
*) echo "steps: host vm rct shot" >&2; exit 2 ;;
esac
