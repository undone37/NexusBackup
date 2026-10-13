#!/usr/bin/env bash
# Windows agent end to end against the dev control plane (lab/linux/e2e.sh appliance), on the PVE lab's
# Windows VMs, driven through the guest agent (lab/windows/gexec.py; no Windows password needed).
# Covers docs/agent-windows.md "Manual test plan" steps 1, 2, 3, 5, 6, 7, 8, 9 and 11 where they can be scripted.
#
#   e2e.sh VMID [steps]     default: msi data agent backup incr restore confine update service
#     msi      MSI install: service config (auto, LocalSystem), failure actions, protected ACL, "not initialised" exit
#     data     test tree C:\nexus-lab\data: explicit DACLs, protected ACL, owner, hidden/system/read-only, ADS,
#              hard link, symlinks, junction, long path, unicode names; firewall rule for TCP 7444
#     agent    create the agent (API), init --token - on the VM, start the service, enroll (job), second enroll 409
#     backup   source + manual backup: VSS shadow set in the log, consistent
#     incr     change 2 files and 1 ADS: the second run re-reads only those
#     restore  restore to C:\nexus-lab\restore\<n>, compare with lab/windows/manifest.ps1
#     confine  junction to C:\Windows inside the target: overwrite=always restore writes nothing under C:\Windows
#     update   agent_update on an MSI install: refused ("package")
#     service  taskkill /f -> SCM restarts the service; sc stop -> stays stopped; start again
# env: as lab/linux/e2e.sh (ROOT, PORT); MSI (target/packages/nexus-agent-<v>-x64.msi); HOST (VM address the
#      appliance connects to; default: from the guest agent)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export ROOT=${ROOT:-$repo/target/linux-root} PORT=${PORT:-18453}
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/crates/agent-windows/Cargo.toml" | head -1)
MSI=${MSI:-$repo/target/packages/nexus-agent-$ver-x64.msi}
TENANT=windows
VMID=${1:?vmid}
shift
eval "$(ROOT=$ROOT PORT=$PORT "$repo/lab/e2e/m5.sh" env)"
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
win() { "$here/gexec.py" "$VMID" "$1"; }
R=$S/win-$VMID.results
touch "$R"
result() {
	grep -v "^$1=" "$R" >"$R.tmp" || true
	echo "$1=$2" >>"$R.tmp"
	mv "$R.tmp" "$R"
	log "result $1=$2"
}
# shellcheck disable=SC1090
state() { [ -f "$S/win-$VMID.env" ] && . "$S/win-$VMID.env"; return 0; }
EXE='C:\Program Files\NexusBackup Agent\nexus-agent.exe'
DATA='C:\nexus-lab\data'

step_msi() {
	[ -f "$MSI" ] || die "no MSI at $MSI (release/packages.sh --test-key --no-arm64)"
	win 'New-Item -ItemType Directory -Force C:\nexus-lab | Out-Null'
	"$here/gexec.py" "$VMID" --put "$MSI" 'C:\nexus-lab\agent.msi' >/dev/null
	# same version again (lab rebuilds): remove first; %ProgramData%\NexusAgent (enrollment) stays
	win '$p = Get-Package "NexusBackup Agent" -ErrorAction SilentlyContinue; if ($p) { Start-Process msiexec -Wait -ArgumentList "/x $($p.FastPackageReference) /qn" }' >&2
	win '$p = Start-Process msiexec -Wait -PassThru -ArgumentList "/i C:\nexus-lab\agent.msi /qn /l*v C:\nexus-lab\msi-install.log"; "msiexec exit $($p.ExitCode)"' >&2
	win 'Get-Package "NexusBackup Agent" -ErrorAction SilentlyContinue | Select-Object -Expand Version' | grep -q . ||
		die "MSI not in installed programs: $(win 'Get-Content C:\nexus-lab\msi-install.log -Tail 30')"
	local qc qf acl
	qc=$(win 'sc.exe qc NexusAgent')
	grep -q AUTO_START <<<"$qc" && grep -q LocalSystem <<<"$qc" && grep -qi 'nexus-agent.exe" service' <<<"$qc" ||
		die "sc qc: $qc"
	qf=$(win 'sc.exe qfailure NexusAgent')
	[ "$(grep -c 'RESTART' <<<"$qf")" -ge 3 ] || die "failure actions: $qf"
	acl=$(win '(Get-Acl $env:ProgramData\NexusAgent | Select-Object -Expand Access | % { "$($_.IdentityReference)" }) -join ","; (Get-Acl $env:ProgramData\NexusAgent).AreAccessRulesProtected')
	grep -qx True <<<"$acl" || die "ProgramData ACL not protected: $acl"
	grep -viE 'SYSTEM|Administrators|Administratoren|^True$' <<<"$(head -1 <<<"$acl" | tr , '\n')" &&
		die "ProgramData ACL grants others: $acl"
	win 'Start-Sleep 3; (Get-Service NexusAgent).Status; Get-Content $env:ProgramData\NexusAgent\state\nexus-agent.log -Tail 3 -ErrorAction SilentlyContinue' >&2
	result msi "installed $ver, auto/LocalSystem, 3 restarts, ACL protected"
}

step_data() {
	win '
$d = "C:\nexus-lab\data"
if (Test-Path $d) { cmd /c rmdir /s /q $d }
New-Item -ItemType Directory -Force $d, "$d\sub", "$d\protected", "$d\deep" | Out-Null
1..50 | % { Set-Content "$d\sub\file$_.txt" ("line $_ " * 200) }
$b = New-Object byte[] 4194304; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [IO.File]::WriteAllBytes("$d\random.bin", $b)
Set-Content "$d\readonly.txt" "ro"; (Get-Item "$d\readonly.txt").Attributes = "ReadOnly"
Set-Content "$d\hidden.txt" "h"; (Get-Item "$d\hidden.txt" -Force).Attributes = "Hidden,System"
Set-Content "$d\streams.txt" "main"; Set-Content "$d\streams.txt" -Stream extra "alternate data"
Set-Content "$d\streams.txt" -Stream Zone.Identifier "[ZoneTransfer]`r`nZoneId=3"
Set-Content "$d\übergröße-日本語-ünïcödé.txt" "unicode"
New-Item -ItemType HardLink -Path "$d\hardlink.txt" -Target "$d\sub\file1.txt" | Out-Null
cmd /c mklink "$d\sym-rel.txt" "sub\file2.txt" | Out-Null
New-Item -ItemType SymbolicLink -Path "$d\sym-dir" -Target "$d\sub" | Out-Null
New-Item -ItemType Junction -Path "$d\junction" -Target "$d\sub" | Out-Null
$p = "\\?\$d\deep" + ("\" + "x" * 60) * 5; [IO.Directory]::CreateDirectory($p) | Out-Null
[IO.File]::WriteAllText("$p\long-path-file.txt", "long")
Set-Content "$d\protected\secret.txt" "s"
$a = Get-Acl "$d\protected"; $a.SetAccessRuleProtection($true, $false)
$a.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$a.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$a.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\NETWORK SERVICE","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")))
Set-Acl "$d\protected" $a
$a = Get-Acl "$d\readonly.txt"; $a.SetOwner([Security.Principal.NTAccount]"NT AUTHORITY\NETWORK SERVICE"); Set-Acl "$d\readonly.txt" $a
if (-not (Get-NetFirewallRule -DisplayName "NexusBackup Agent lab" -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName "NexusBackup Agent lab" -Direction Inbound -Protocol TCP -LocalPort 7444 -Action Allow | Out-Null }
(Get-ChildItem $d -Recurse -Force | Measure-Object).Count'
}

step_agent() {
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	LOGGED=1
	api admin GET /tenants | jq -e --arg t "$TENANT" '.[] | select(.name==$t)' >/dev/null ||
		{ api admin POST /tenants "$(jq -nc --arg t "$TENANT" '{name:$t}')" >/dev/null && expect 201 "create tenant"; }
	local host=${HOST:-} name r id tok j
	[ -n "$host" ] || host=$(win '(Get-NetIPAddress -AddressFamily IPv4 | ? { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } | Select -First 1).IPAddress')
	name=$(win 'hostname' | tr -d '\r\n')
	r=$(api admin POST /agents "$(jq -nc --arg t "$TENANT" --arg n "$name" --arg h "$host" '{tenant:$t, name:$n, host:$h, port:7444}')")
	expect 201 "create agent"
	id=$(jq -r .id <<<"$r")
	tok=$(jq -r .token <<<"$r")
	printf 'AGENT=%s\nNAME=%s\n' "$id" "$name" >"$S/win-$VMID.env"
	# the token goes in on stdin, as the manual says (not on the command line)
	win "Set-Content C:\\nexus-lab\\tok -NoNewline '$tok'; Get-Content C:\\nexus-lab\\tok | & '$EXE' init --token -; Remove-Item C:\\nexus-lab\\tok; Start-Service NexusAgent; Start-Sleep 2; (Get-Service NexusAgent).Status" >&2
	step_enroll
}

# enroll job (part of `agent`; alone: retry after a failed enrollment)
step_enroll() {
	state
	[ -n "${LOGGED:-}" ] || login admin "$ADMIN_PW" "$ADMIN_TOTP"
	LOGGED=1
	local id=$AGENT r j t0=$SECONDS
	r=$(api admin POST "/agents/$id/enroll")
	expect 202 "enroll"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "enroll: $(jq -r .log <<<"$j" | tail -n 20)"
	result enroll_s $((SECONDS - t0))
	api admin GET /agents | jq -c --arg id "$id" '.[] | select(.id==$id) | {name, version, os, host}' >&2
	api admin POST "/agents/$id/enroll" >/dev/null
	[ "$(status)" = 409 ] || die "second enroll: HTTP $(status)"
	win "& '$EXE' status" | sed 's/^/  vm: /' >&2
}

backup() { # -> job json; the snapshot time goes to the VM's env file (LAST)
	local r j
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"backup", tenant:$t, params:{agent_id:$a}}')")
	expect 202 "backup"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 3600)
	[ "$(jq -r .result.time <<<"$j")" = null ] || echo "LAST=$(jq -r .result.time <<<"$j")" >>"$S/win-$VMID.env"
	echo "$j"
}
committed() { jq -r .log <<<"$1" | grep -m1 '^committed ' || true; }

step_backup() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local src j
	src=$(api admin GET /sources | jq -r --arg n "$NAME" '.[] | select(.name==$n) | .id')
	if [ -z "$src" ]; then
		api admin POST /sources "$(jq -nc --arg t "$TENANT" --arg n "$NAME" --arg a "$AGENT" --arg d "$DATA" \
			'{tenant:$t, kind:"linux", name:$n, config:{agent_id:$a, paths:[$d, "C:\\Users"], excludes:["*.tmp"]}}')" >/dev/null
		expect 201 "create source"
	fi
	j=$(backup)
	jq -r .log <<<"$j" | grep -iE 'shadow|writer|vss|inconsistent|error|warn' | head -20 | sed 's/^/  log: /' >&2 || true
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 30)"
	log "$(committed "$j")"
	jq -r .log <<<"$j" | grep -q '^inconsistent ' && die "backup not consistent (VSS)"
	win 'vssadmin list shadows | Select-String "Shadow Copy ID" | Measure-Object | % Count' | grep -qx 0 ||
		die "shadow copies left after the backup"
	result backup "$(jq '.finished - .started' <<<"$j") s, VSS, consistent, no shadow copies left"
}

step_incr() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	win '$d="C:\nexus-lab\data"; Add-Content "$d\sub\file3.txt" "changed"; Set-Content "$d\new.txt" "new"; Set-Content "$d\streams.txt" -Stream extra "changed stream"' >/dev/null
	local j c
	j=$(backup)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "incremental: $(jq -r .log <<<"$j" | tail -n 30)"
	c=$(committed "$j")
	log "$c"
	jq -r .log <<<"$j" | grep -iE 'usn|journal|unchanged' | head -5 | sed 's/^/  log: /' >&2 || true
	result incr "$(sed -n 's/.* \([0-9]*\) unchanged files.*/\1/p' <<<"$c") unchanged, $(sed -n 's/.*chunks transferred (\([0-9]*\) bytes.*/\1/p' <<<"$c") bytes transferred"
}

# the last backup's snapshot, once the catalog lists it (refreshed asynchronously)
latest() {
	local i
	for i in $(seq 90); do
		api admin GET "/snapshots?tenant=$TENANT" | jq -e --arg s "host-$AGENT" --argjson t "$LAST" '.[] | select(.source==$s and .time==$t)' >/dev/null && break
		[ "$i" = 90 ] && die "snapshot $LAST not in the catalog"
		sleep 2
	done
	echo "$LAST"
}
restore() { # target overwrite -> job json
	local r
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg s "host-$AGENT" --argjson tm "$(latest)" --arg d "$DATA" --arg tg "$1" --arg o "$2" --arg c "$NAME" \
		'{kind:"restore_files", tenant:$t, params:{source:$s, time:$tm, paths:[$d], target:$tg, overwrite:$o, confirm:$c}}')")
	expect 202 "restore_files"
	wait_job admin "$(jq -r .id <<<"$r")" 3600
}

step_restore() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local t j
	t="C:\\nexus-lab\\restore\\$(date +%s)"
	j=$(restore "$t" never)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "restore: $(jq -r .log <<<"$j" | tail -n 30)"
	log "restored: $(jq -c .result <<<"$j")"
	"$here/gexec.py" "$VMID" --put "$here/manifest.ps1" 'C:\nexus-lab\manifest.ps1' >/dev/null
	local rest
	rest=$(win "Get-ChildItem -LiteralPath '$t' -Recurse -Filter data -Directory | Select -First 1 -Expand FullName")
	[ -n "$rest" ] || die "no data directory under $t"
	win "& C:\\nexus-lab\\manifest.ps1 '$DATA' > C:\\nexus-lab\\m.orig; & C:\\nexus-lab\\manifest.ps1 '$rest' > C:\\nexus-lab\\m.rest; Compare-Object (Get-Content C:\\nexus-lab\\m.orig) (Get-Content C:\\nexus-lab\\m.rest) | Format-Table -Wrap | Out-String -Width 400" >"$S/win-$VMID.diff"
	if grep -q '=>\|<=' "$S/win-$VMID.diff"; then
		log "restore differs:"
		head -40 "$S/win-$VMID.diff" >&2
		result restore_identical no
	else
		result restore_identical "$(win '(Get-Content C:\nexus-lab\m.orig).Count') entries"
	fi
	echo "TARGET='$t'" >>"$S/win-$VMID.env"
}

step_confine() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local t j
	t="C:\\nexus-lab\\confine\\$(date +%s)"
	# the restore will create <t>\nexus-lab\data\...: plant a junction at <t>\nexus-lab pointing into C:\Windows
	win "New-Item -ItemType Directory -Force '$t' | Out-Null; New-Item -ItemType Directory -Force C:\\Windows\\Temp\\nexus-trap | Out-Null; New-Item -ItemType Junction -Path '$t\\nexus-lab' -Target C:\\Windows\\Temp\\nexus-trap | Out-Null" >/dev/null
	j=$(restore "$t" always)
	log "restore through a junction: state $(jq -r .state <<<"$j"), $(jq -r .log <<<"$j" | grep -iE 'error|refus|reparse|junction' | head -3 | tr '\n' ' ')"
	win '(Get-ChildItem C:\Windows\Temp\nexus-trap -Recurse -Force | Measure-Object).Count' | grep -qx 0 ||
		die "restore wrote through the junction into C:\\Windows\\Temp\\nexus-trap"
	result confine "nothing written through the junction"
}

step_update() {
	state
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	local r j u=$ROOT/agent-update w=$repo/target/agent-dist/windows
	# one update directory per appliance today (no per-OS bundles): stage the Windows build, signed
	mkdir -p "$u"
	install -m 0644 "$w/nexus-agent.exe" "$u/nexus-agent"
	install -m 0644 "$w/nexus-agent.version" "$u/nexus-agent.version"
	COSIGN_KEY=$repo/release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
		"$repo/release/sign.sh" sign-blob "$u/nexus-agent" "$u/nexus-agent.sig" >/dev/null
	r=$(api admin POST /jobs "$(jq -nc --arg t "$TENANT" --arg a "$AGENT" '{kind:"agent_update", tenant:$t, params:{agent_id:$a}}')")
	expect 202 "agent_update"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
	[ "$(jq -r .state <<<"$j")" = failed ] || die "update of an MSI install was not refused"
	result update_msi "refused: $(jq -r .log <<<"$j" | grep -iE 'package|msi|self.update' | head -1)"
}

step_service() {
	local s
	win 'taskkill /f /im nexus-agent.exe | Out-Null; Start-Sleep 75; (Get-Service NexusAgent).Status' | tail -1 | grep -qx Running ||
		die "service not restarted after taskkill"
	win 'Stop-Service NexusAgent; Start-Sleep 70; (Get-Service NexusAgent).Status' | tail -1 | grep -qx Stopped ||
		die "service restarted after a clean stop"
	s=$(win 'Start-Service NexusAgent; Start-Sleep 2; (Get-Service NexusAgent).Status' | tail -1)
	[ "$s" = Running ] || die "service does not start: $s"
	result service "taskkill -> restarted, stop -> stays stopped"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(msi data agent backup incr restore confine update service)
for s in "${steps[@]}"; do
	log "== $VMID: $s"
	"step_$s"
done
log "$VMID done; results in $R"
cat "$R"
