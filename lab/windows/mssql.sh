#!/usr/bin/env bash
# SQL Server lab (#41, docs/database-logs-design.md): a clone of the lab Windows Server 2022 (VM 242) with SQL Server
# 2022 Developer edition (licence accepted by the maintainer, 2026-11-02; downloaded from Microsoft by the VM itself,
# nothing of it in the repository), a database in the FULL recovery model and a table that gets a row per second.
# Driven through the guest agent (gexec.py); T-SQL through PowerShell's System.Data.SqlClient as SYSTEM (sysadmin).
#
#   mssql.sh host     VM $VMID: full clone of VM 242, 8 GB, renamed nx-mssql, restarted
#   mssql.sh install  SQL Server 2022 Developer, default instance, from Microsoft's ISO (setup.exe /Q)
#   mssql.sh db       database labdb (FULL), table ticks; a scheduled task inserts one row per second
#   mssql.sh sshd     OpenSSH server (Windows capability), local administrator nexus with the key
#                     $LAB/nexus_ed25519 (administrators_authorized_keys), a sysadmin login for it, the staging
#                     folder C:\NexusBackup\staging writable by the SQL Server service; prints the host key line
#   mssql.sh static   fixed address $ADDR (gateway .254, DNS .253 of the lab network), kept in $LAB/host
#   mssql.sh sql SQL  runs SQL (prints the first column of every row)
#   mssql.sh destroy  stop and remove the VM
#
# env: VMID (268), LAB (~/nexus-lab/mssql-win), ADDR (10.2.34.247)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
VMID=${VMID:-268}
PVE_HOST=${PVE_HOST:-10.2.34.200}
SSH_KEY=${SSH_KEY:-$HOME/nexus-lab/pve-lab-key}
LAB=${LAB:-$HOME/nexus-lab/mssql-win}
mkdir -p "$LAB" && chmod 700 "$LAB"
ADDR=${ADDR:-10.2.34.247}
ISO=${ISO:-https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLServer2022-x64-ENU-Dev.iso}
[ "$VMID" -ge 200 ] || { echo "VMID $VMID: only VMs from 200 are ours" >&2; exit 1; }
win() { "$here/gexec.py" "$VMID" "$1"; }
pve() { ssh -n -i "$SSH_KEY" -o BatchMode=yes "root@$PVE_HOST" "$@" 2> >(grep -v 'older storage API' >&2); }
wait_agent() { for _ in $(seq 1 90); do win 'exit 0' >/dev/null 2>&1 && return; sleep 10; done; echo "no guest agent" >&2; exit 1; }
# PowerShell that runs T-SQL on the default instance (integrated security) and prints the first column
SQLPS='function Sql($q) { $c = New-Object System.Data.SqlClient.SqlConnection "Server=.;Integrated Security=SSPI;TrustServerCertificate=true;Connect Timeout=30"
	$c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $q; $cmd.CommandTimeout = 0; $r = $cmd.ExecuteReader()
	do { while ($r.Read()) { [string]$r.GetValue(0) } } while ($r.NextResult()); $c.Close() }'

case ${1:?step} in
host)
	pve "qm status $VMID >/dev/null 2>&1 || { qm clone 242 $VMID --name nx-mssql --full >/dev/null &&
		qm set $VMID --memory 8192 --cores 4 --tags nexus-mssql-lab >/dev/null; }; qm start $VMID 2>/dev/null || true"
	wait_agent
	win 'if ($env:COMPUTERNAME -ne "NX-MSSQL") { Rename-Computer -NewName nx-mssql -Force -WarningAction SilentlyContinue; shutdown /r /t 5 | Out-Null }'
	sleep 90
	wait_agent
	win '"$env:COMPUTERNAME"'
	;;
install)
	# the Developer ISO from Microsoft (the SSEI bootstrapper hangs when run as SYSTEM through the guest agent)
	GEXEC_TIMEOUT=3600 win '$ErrorActionPreference = "Stop"; $ProgressPreference = "SilentlyContinue"
		if (Get-Service MSSQLSERVER -ErrorAction SilentlyContinue) { "installed"; exit 0 }
		New-Item -ItemType Directory -Force C:\sqlsetup | Out-Null
		$iso = "C:\sqlsetup\SQLServer2022-x64-ENU-Dev.iso"
		if (-not (Test-Path $iso)) { Invoke-WebRequest -UseBasicParsing "'"$ISO"'" -OutFile $iso }
		$d = (Mount-DiskImage $iso -PassThru | Get-Volume).DriveLetter
		$s = Get-AuthenticodeSignature "${d}:\setup.exe"
		if ($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") { throw "setup.exe signature: $($s.Status) $($s.SignerCertificate.Subject)" }
		$p = Start-Process "${d}:\setup.exe" -Wait -PassThru -ArgumentList "/Q","/ACTION=Install","/FEATURES=SQLENGINE","/INSTANCENAME=MSSQLSERVER","/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`" `"NT AUTHORITY\SYSTEM`"","/IACCEPTSQLSERVERLICENSETERMS","/UPDATEENABLED=0","/TCPENABLED=1"
		Dismount-DiskImage $iso | Out-Null
		"setup exit $($p.ExitCode)"; Get-Service MSSQLSERVER | Format-Table -AutoSize Name, Status | Out-String'
	;;
db)
	win "$SQLPS
$(
		cat <<'PS'
Sql "IF DB_ID('labdb') IS NULL CREATE DATABASE labdb" | Out-Null
Sql "ALTER DATABASE labdb SET RECOVERY FULL" | Out-Null
Sql "USE labdb; IF OBJECT_ID('dbo.ticks') IS NULL CREATE TABLE dbo.ticks (id int IDENTITY PRIMARY KEY, t datetime2 NOT NULL DEFAULT sysutcdatetime())" | Out-Null
Set-Content C:\sqlsetup\ticks.ps1 'while ($true) { $c = New-Object System.Data.SqlClient.SqlConnection "Server=.;Database=labdb;Integrated Security=SSPI;TrustServerCertificate=true"; try { $c.Open(); while ($true) { $k = $c.CreateCommand(); $k.CommandText = "INSERT INTO dbo.ticks DEFAULT VALUES"; [void]$k.ExecuteNonQuery(); Start-Sleep 1 } } catch { Start-Sleep 5 } finally { $c.Dispose() } }'
if (-not (Get-ScheduledTask nexus-ticks -ErrorAction SilentlyContinue)) {
	Register-ScheduledTask nexus-ticks -User SYSTEM -RunLevel Highest -Trigger (New-ScheduledTaskTrigger -AtStartup) -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -File C:\sqlsetup\ticks.ps1") | Out-Null }
Start-ScheduledTask nexus-ticks; Start-Sleep 5
"recovery: " + (Sql "SELECT recovery_model_desc FROM sys.databases WHERE name = 'labdb'")
"ticks: " + (Sql "SELECT COUNT(*) FROM labdb.dbo.ticks")
PS
	)"
	;;
sshd)
	[ -f "$LAB/nexus_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C nexus-mssql-lab -f "$LAB/nexus_ed25519"
	pw="Nx$(openssl rand -hex 12)!"
	GEXEC_TIMEOUT=1800 win "$SQLPS
$(
		cat <<'PS' | sed -e "s|@PW@|$pw|" -e "s|@PUB@|$(cat "$LAB/nexus_ed25519.pub")|"
$ErrorActionPreference = "Stop"
if ((Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0).State -ne "Installed") { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }
Set-Service sshd -StartupType Automatic; Start-Service sshd
if (-not (Get-NetFirewallRule -Name sshd-nexus -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name sshd-nexus -DisplayName "OpenSSH (NexusBackup lab)" -Protocol TCP -LocalPort 22 -Direction Inbound -Action Allow | Out-Null }
if (-not (Get-LocalUser nexus -ErrorAction SilentlyContinue)) { New-LocalUser nexus -Password (ConvertTo-SecureString '@PW@' -AsPlainText -Force) -PasswordNeverExpires | Out-Null; Add-LocalGroupMember Administrators nexus }
$k = "C:\ProgramData\ssh\administrators_authorized_keys"
Set-Content $k '@PUB@'
icacls $k /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
New-Item -ItemType Directory -Force C:\NexusBackup\staging | Out-Null
icacls C:\NexusBackup /grant "NT SERVICE\MSSQLSERVER:(OI)(CI)M" | Out-Null
Sql "IF SUSER_ID(N'NX-MSSQL\nexus') IS NULL CREATE LOGIN [NX-MSSQL\nexus] FROM WINDOWS; ALTER SERVER ROLE sysadmin ADD MEMBER [NX-MSSQL\nexus]; SELECT 1" | Out-Null
"address: " + (Get-NetIPAddress -AddressFamily IPv4 | ? { $_.IPAddress -notlike '127.*' } | Select -First 1).IPAddress
Get-Content C:\ProgramData\ssh\ssh_host_ed25519_key.pub
PS
	)" | tee "$LAB/sshd.out"
	grep '^ssh-ed25519' "$LAB/sshd.out" | tr -d '\r' >"$LAB/host_key"
	sed -n 's/^address: //p' "$LAB/sshd.out" | tr -d '\r' >"$LAB/host"
	;;
static)
	# through the guest agent, which does not depend on the network
	win 'Set-NetIPInterface -InterfaceAlias Ethernet -Dhcp Disabled
		Remove-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
		Remove-NetRoute -InterfaceAlias Ethernet -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue
		New-NetIPAddress -InterfaceAlias Ethernet -IPAddress '"$ADDR"' -PrefixLength 24 -DefaultGateway 10.2.34.254 | Out-Null
		Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.2.34.253
		(Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress'
	echo "$ADDR" >"$LAB/host"
	;;
sql)
	win "$SQLPS
		Sql @'
${*:2}
'@"
	;;
destroy)
	pve "qm stop $VMID 2>/dev/null; qm destroy $VMID --purge 2>/dev/null" || true
	;;
esac
