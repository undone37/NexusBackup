#!/usr/bin/env bash
# Plugin platform lab (docs/plugin-system.md) on one appliance VM, SELinux enforcing,
# no PVE lab needed: the example plugin (plugins/example-files) backs up a directory
# of the appliance itself.
#   plugins.sh image    build $IMG + $IMG-lab (lab/appliance/e2e.sh image)
#   plugins.sh bundle   build the example plugin on the host, pack it (nexus-plugin pack),
#                       sign it with the TEST key (release/sign.sh sign-blob)
#   plugins.sh disk     install the lab image onto $LAB/appliance/appliance.qcow2
#   plugins.sh boot     boot it, wait for the console
#   plugins.sh setup    first boot (e2e.sh setup with PVE=0)
#   plugins.sh plugin   bundle; tampered upload refused; upload (admin) -> quorum (so approves)
#                       -> installed; tenant + plugin source on $DATA; plugin_validate,
#                       plugin_guests; group + policy; backup, second backup (incremental);
#                       files_list + files_get, sha256 of every file against $DATA in the VM;
#                       nexus_pluginhost_t / nexus_plugin_t observed during the backup
#   plugins.sh check    e2e.sh check, install tree labels, 0 nexus AVCs since boot
#   plugins.sh stop     power off
# e.g. IMG=localhost/nexus-os:plugins lab/appliance/plugins.sh image disk boot setup plugin check stop
# env: IMG (localhost/nexus-os:plugins), LAB (/home/ah/nexus-lab/plugins; the installer root is
#      reused from LABDIR=/home/ah/nexus-lab), PORT (28481), MEM (3072), DATA (/usr/share/doc:
#      read-only data the plugin sandbox may read: Landlock allows /usr, SELinux usr_t),
#      PLUGIN_TARGET (gnu: dynamically linked against glibc like the image's libraries, checked
#      for GLIBC <= 2.39 (AlmaLinux 10); musl: static)
# Needs ~3 GB free RAM for the VM (plus the image build); cargo + podman on the host.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export IMG=${IMG:-localhost/nexus-os:plugins}
LABDIR=${LABDIR:-/home/ah/nexus-lab}
export LAB=${LAB:-$LABDIR/plugins}
export PORT=${PORT:-28481}
export ROOT=$LAB/appliance/root CONSOLE=$LAB/appliance/console.sock PVE=0
DATA=${DATA:-/usr/share/doc}
PLUGIN_TARGET=${PLUGIN_TARGET:-gnu}
MANIFEST=$repo/plugins/example-files/manifest.json
OUT=$LAB/bundle
T0=$(date +%s)
con() { "$here/con.py" "$@"; }

image() { "$here/e2e.sh" image; }

bundle() {
	local id ver bin tgt=() maxglibc
	id=$(jq -r .id "$MANIFEST")
	ver=$(jq -r .version "$MANIFEST")
	mkdir -p "$OUT"
	[ "$PLUGIN_TARGET" = musl ] && tgt=(--target x86_64-unknown-linux-musl)
	log "building the example plugin ($PLUGIN_TARGET)"
	(cd "$repo" && cargo build --release -p example-files "${tgt[@]}")
	bin=$repo/target/release/example-files
	[ "$PLUGIN_TARGET" = musl ] && bin=$repo/target/x86_64-unknown-linux-musl/release/example-files
	if [ "$PLUGIN_TARGET" = gnu ]; then
		maxglibc=$(objdump -T "$bin" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
		[ "$(printf '%s\nGLIBC_2.39\n' "$maxglibc" | sort -V | tail -1)" = GLIBC_2.39 ] ||
			die "example-files needs $maxglibc (> AlmaLinux 10's 2.39): use PLUGIN_TARGET=musl"
		log "dynamically linked, needs up to $maxglibc"
	fi
	B=$OUT/$id-$ver.nxplugin
	rm -f "$B" "$B.sig"
	(cd "$repo" && cargo run -q -p plugin-sdk --features cli --bin nexus-plugin -- pack "$MANIFEST" "$bin" "$B")
	COSIGN_KEY=$repo/release/testkey/TEST-cosign.key COSIGN_PASSWORD=nexus-test-key \
		"$repo/release/sign.sh" sign-blob "$B" "$B.sig"
	log "bundle $B ($(stat -c %s "$B") bytes), signature $B.sig"
}

disk() {
	mkdir -p "$LAB/appliance/work"
	# reuse the shared lab's installer root (12 GB sparse) if this lab has none yet
	if [ ! -f "$LAB/appliance/work/installer.raw" ] && [ -f "$LABDIR/appliance/work/installer.raw" ]; then
		cp --sparse=always "$LABDIR/appliance/work/installer."{raw,vmlinuz,initrd,id} "$LAB/appliance/work/"
	fi
	"$here/build-disk.sh" "$IMG-lab"
}

boot() { "$here/e2e.sh" boot; }

setup() {
	"$here/e2e.sh" setup
	con run 'systemctl is-enabled nexus-plugin-install.path nexus-plugin-install.service; systemctl is-active nexus-plugin-install.path; ls -ldZ /var/lib/nexus/plugins /var/lib/nexus/plugins-staging /etc/pki/nexus/plugin-keys/*'
}

apienv() {
	S=$ROOT/run/api
	mkdir -p "$S"
	# shellcheck disable=SC1091
	. "$ROOT/secrets.env"
	# shellcheck source=lab/e2e/api-lib.sh
	. "$repo/lab/e2e/api-lib.sh"
}

# upload BUNDLE SIG -> body (admin; raw bytes + X-Plugin-Signature), status in $S/status
upload() {
	curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" \
		-b "$S/admin.jar" -c "$S/admin.jar" -X POST -H "X-CSRF-Token: $(cat "$S/admin.csrf")" \
		-H 'Content-Type: application/octet-stream' -H "X-Plugin-Signature: $(tr -d '\n' <"$2")" \
		--data-binary @"$1" -o "$S/body" -w '%{http_code}' "$BASE/plugins" >"$S/status"
	cat "$S/body"
}

# job USER KIND PARAMS [timeout] -> final job JSON (dies unless ok)
job() {
	local r j
	r=$(api "$1" POST /jobs "$(jq -nc --arg k "$2" --argjson p "$3" '{kind:$k, tenant:"plugins", params:$p}')")
	expect 202 "$2 job"
	j=$(wait_job "$1" "$(jq -r .id <<<"$r")" "${4:-900}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$2: $(jq -r .log <<<"$j" | tail -n 30)"
	echo "$j"
}

# backup GROUP -> logs the result; records the plugin domains seen in the VM meanwhile
backup() {
	local r j
	con run 'rm -f /run/nexus-lab-ps; setsid sh -c "for i in \$(seq 600); do ps -eo label,comm | grep -E \"nexus_plugin(host)?_t\" >>/run/nexus-lab-ps; sleep 0.2; done" </dev/null >/dev/null 2>&1 &' >/dev/null
	r=$(api admin POST /jobs "$(jq -nc --argjson g "$1" '{kind:"backup", tenant:"plugins", params:{group_id:$g}}')")
	expect 202 "backup job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 30)"
	log "backup job $(jq -r .id <<<"$j") ok in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
	log "domains during the backup: $(con run 'sort -u /run/nexus-lab-ps 2>/dev/null | sed "s/  */ /g"' | tr '\n' ';')"
}

plugin() {
	bundle
	apienv
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	local id kind r q st e src pol grp j snap time ents paths want have

	id=$(jq -r .id "$MANIFEST")
	kind=$(jq -r '.kinds[0].kind' "$MANIFEST")
	# a bundle that does not match its signature is refused before any quorum
	cp "$B" "$OUT/tampered.nxplugin"
	printf 'x' >>"$OUT/tampered.nxplugin"
	upload "$OUT/tampered.nxplugin" "$B.sig" >/dev/null
	expect 400 "tampered bundle must be refused"
	log "tampered bundle refused: $(cat "$S/body")"

	r=$(upload "$B" "$B.sig")
	expect 202 "upload plugin"
	q=$(jq -r .quorum_id <<<"$r")
	log "uploaded: $(jq -c '.plugin | {id, version, state, signer, sha256}' <<<"$r"), quorum $q"
	api admin POST "/quorum/$q/approve" '{}' >/dev/null
	expect 403 "admin may not approve his own plugin install"
	api so POST "/quorum/$q/approve" '{}' >/dev/null
	expect 200 "so approves the install"
	for _ in $(seq 180); do
		e=$(api admin GET /plugins | jq -c --arg id "$id" '[.[] | select(.id==$id)] | max_by(.uploaded_at)')
		st=$(jq -r .state <<<"$e")
		case $st in installed | failed | rejected) break ;; esac
		sleep 1
	done
	[ "$st" = installed ] || die "plugin $id: state $st: $(jq -r .error <<<"$e"); $(con run 'journalctl -u nexus-plugin-install -o cat --no-pager | tail -n 20')"
	log "installed: $(jq -c '{id, version, state, current, enabled, signer, bin_sha256}' <<<"$e")"
	con run "ls -lZR /var/lib/nexus/plugins/$id | head -n 30; ls -la /var/lib/nexus/plugins-staging"

	api admin POST /tenants '{"name":"plugins"}' >/dev/null
	expect 201 "create tenant"
	src=$(api admin POST /sources "$(jq -nc --arg k "plugin:$kind" --arg p "$DATA" \
		'{tenant:"plugins", kind:$k, name:"appliance-docs", config:{path:$p, excludes:[]}}')" | jq -r .id)
	expect 201 "create plugin source"
	j=$(job admin plugin_validate "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
	jq -e '.result.valid == true' <<<"$j" >/dev/null || die "plugin_validate: $(jq -c .result <<<"$j")"
	log "plugin_validate: $(jq -c .result <<<"$j")"
	if jq -e '.kinds[0].guests.list == true' "$MANIFEST" >/dev/null; then
		j=$(job admin plugin_guests "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
		log "plugin_guests: $(jq -c '[.result.guests[].id]' <<<"$j")"
	else
		# a kind without a guest list: the API may refuse the job or the plugin answers []
		r=$(api admin POST /jobs "$(jq -nc --argjson s "$src" '{kind:"plugin_guests", tenant:"plugins", params:{source_id:$s}}')")
		if [ "$(status)" = 202 ]; then
			j=$(wait_job admin "$(jq -r .id <<<"$r")" 300)
			log "plugin_guests (kind without guest list): $(jq -c '{state, result}' <<<"$j")"
		else
			log "plugin_guests (kind without guest list): HTTP $(status) $r"
		fi
	fi

	pol=$(api admin POST /policies '{"name":"plugins","schedule":"daily 04:44","gfs":{"daily":14,"weekly":4,"monthly":6,"yearly":2},"offsite":false}' | jq -r .id)
	expect 201 "create policy"
	grp=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" \
		'{tenant:"plugins", source_id:$s, policy_id:$p, name:"docs", guests:[]}')" | jq -r .id)
	expect 201 "create group"
	backup "$grp"
	sleep 2 # second snapshot needs a later time stamp
	backup "$grp"

	snap=$(api admin GET '/snapshots?tenant=plugins' | jq -c '[.[] | select(.source | startswith("plugin-"))] | sort_by(.time)')
	[ "$(jq length <<<"$snap")" -ge 2 ] || die "want 2 plugin snapshots: $snap"
	log "snapshots: $(jq -c '[.[] | {source, time, size}]' <<<"$snap")"
	time=$(jq -r '.[-1].time' <<<"$snap")
	snap=$(jq -r '.[-1].source' <<<"$snap")
	j=$(job admin files_list "$(jq -nc --arg s "$snap" --argjson t "$time" '{source:$s, time:$t, path:"/"}')")
	ents=$(jq -c '[.result.entries[].name | select(. != ".nexus-streams")]' <<<"$j")
	log "$snap@$time / = $(jq -c '.[:10]' <<<"$ents") ($(jq length <<<"$ents") entries)"
	paths=$(jq -c '[.[] | "/" + .]' <<<"$ents")
	r=$(api admin POST /jobs "$(jq -nc --arg s "$snap" --argjson t "$time" --argjson p "$paths" \
		'{kind:"files_get", tenant:"plugins", params:{source:$s, time:$t, paths:$p, format:"tar"}}')")
	expect 202 "files_get"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "files_get: $(jq -r .log <<<"$j" | tail -n 30)"
	api admin GET "/downloads/$(jq -r .download_token <<<"$r")" >/dev/null
	expect 200 "download"
	rm -rf "$S/restored"
	mkdir -p "$S/restored"
	tar -xf "$S/body" -C "$S/restored"
	# compare file contents (sha256 of every regular file; paths may carry a prefix in the tar)
	have=$(cd "$S/restored" && find . -type f -print0 | xargs -0r sha256sum | cut -d' ' -f1 | sort | sha256sum | cut -c1-16)
	have="$have $(find "$S/restored" -type f | wc -l)"
	want=$(con run "cd '$DATA' && h=\$(find . -type f -print0 | xargs -0r sha256sum | cut -d' ' -f1 | sort | sha256sum | cut -c1-16); echo \"\$h \$(find . -type f | wc -l)\"" | tr -d '\r\n')
	[ "$have" = "$want" ] || die "download differs from $DATA in the VM: have $have, want $want"
	log "files_get: $(echo "$have" | cut -d' ' -f2) files, sha256 identical to $DATA in the VM"
}

check() {
	"$here/e2e.sh" check
	con run 'echo "== plugin units"; systemctl is-enabled nexus-plugin-install.path; systemctl show -p Result,ExecMainStatus nexus-plugin-install.service
echo "== install tree labels (bin/plugin must be nexus_plugin_exec_t)"; find /var/lib/nexus/plugins -maxdepth 4 -exec ls -dZ {} + | head -n 20
ls -Z /usr/libexec/nexus/nexus-pluginhost /usr/libexec/nexus/nexus-plugin-install /usr/bin/nexus-plugin
echo "== domains seen during backups"; sort -u /run/nexus-lab-ps 2>/dev/null | sed "s/  */ /g"' 120
	local n
	n=$(con run 'ausearch -m avc,user_avc,selinux_err -ts boot 2>/dev/null | grep -cE "context=[^ ]*nexus_" || true' | tr -d '\r\n')
	con run 'ausearch -m avc,user_avc,selinux_err -ts boot 2>/dev/null | grep -E "context=[^ ]*nexus_" | tail -n 10' || true
	[ "$n" = 0 ] || die "$n AVC/SELinux error records with a nexus context since boot"
	con run 'grep -q nexus_pluginhost_t /run/nexus-lab-ps && grep -q nexus_plugin_t /run/nexus-lab-ps' >/dev/null ||
		log "WARN: nexus_pluginhost_t / nexus_plugin_t not observed (job too short for the 0.2 s poll?)"
	log "check: 0 nexus AVCs since boot"
}

stop() { "$here/run.sh" stop; }

log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

[ $# -gt 0 ] || { sed -n '2,25p' "$0" >&2; exit 2; }
for step in "$@"; do
	case $step in
	image | bundle | disk | boot | setup | plugin | check | stop) "$step" ;;
	*) sed -n '2,25p' "$0" >&2; exit 2 ;;
	esac
done
