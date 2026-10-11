#!/usr/bin/env bash
# Plugin platform lab (docs/plugin-system.md) on one appliance VM, SELinux enforcing,
# no PVE lab needed: the example plugin (plugins/example-files) backs up a directory
# of the appliance itself.
#   plugins.sh image    build $IMG + $IMG-lab (lab/appliance/e2e.sh image)
#   plugins.sh bundle   build the plugin $PLUGIN on the host, pack it (nexus-plugin pack),
#                       sign it with the TEST key (release/sign.sh sign-blob)
#   plugins.sh install  bundle; tampered upload refused; upload (admin) -> quorum (so approves)
#                       -> installed (e.g. PLUGIN=truenas for lab/truenas/e2e.sh KIND=plugin)
#   plugins.sh disk     install the lab image onto $LAB/appliance/appliance.qcow2
#   plugins.sh boot     boot it, wait for the console
#   plugins.sh setup    first boot (e2e.sh setup with PVE=0)
#   plugins.sh plugin   install (example plugin); tenant + plugin source on $DATA; plugin_validate,
#                       plugin_guests; group + policy; backup, second backup (incremental);
#                       files_list + files_get, sha256 of every file against $DATA in the VM;
#                       nexus_pluginhost_t / nexus_plugin_t observed during the backup
#   plugins.sh pg       PLUGIN=postgresql: install; plugins/postgresql/testbox (host 10.0.2.2 from the VM);
#                       validate, guests, backup of database labdb, restore to_target on the alternate
#                       server (labdb_copy), contents compared with the original
#   plugins.sh oidc     single sign-on against crates/web-api/tests/oidc-testbox (TLS=1, Keycloak as kc.nexus-lab):
#                       settings via quorum, connection test from the appliance (egress + SELinux), browser-less
#                       logins: kc-alice -> admin, kc-tina -> tenant user, kc-nobody -> refused (oidc_error=denied)
#   plugins.sh check    e2e.sh check, install tree labels, 0 nexus AVCs since boot
#   plugins.sh stop     power off
# e.g. IMG=localhost/nexus-os:plugins lab/appliance/plugins.sh image disk boot setup plugin check stop
# env: PLUGIN (example-files: the directory below plugins/), IMG (localhost/nexus-os:plugins),
#      LAB (/home/ah/nexus-lab/plugins; the installer root is
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
PLUGIN=${PLUGIN:-example-files}
MANIFEST=$repo/plugins/$PLUGIN/manifest.json
PKG=$(sed -n 's/^name = "\(.*\)"/\1/p' "$repo/plugins/$PLUGIN/Cargo.toml" | head -n 1)
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
	# ring's C code is freestanding: the host gcc works when no musl cross compiler is installed
	[ "$PLUGIN_TARGET" = musl ] && ! command -v x86_64-linux-musl-gcc >/dev/null &&
		export CC_x86_64_unknown_linux_musl=${CC_x86_64_unknown_linux_musl:-gcc}
	log "building the plugin $PKG ($PLUGIN_TARGET)"
	(cd "$repo" && cargo build --release -p "$PKG" "${tgt[@]}")
	bin=$repo/target/release/$PKG
	[ "$PLUGIN_TARGET" = musl ] && bin=$repo/target/x86_64-unknown-linux-musl/release/$PKG
	if [ "$PLUGIN_TARGET" = gnu ]; then
		maxglibc=$(objdump -T "$bin" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
		[ "$(printf '%s\nGLIBC_2.39\n' "$maxglibc" | sort -V | tail -1)" = GLIBC_2.39 ] ||
			die "$PKG needs $maxglibc (> AlmaLinux 10's 2.39): use PLUGIN_TARGET=musl"
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
	r=$(api "$1" POST /jobs "$(jq -nc --arg k "$2" --arg t "${TENANT:-plugins}" --argjson p "$3" '{kind:$k, tenant:$t, params:$p}')")
	expect 202 "$2 job"
	j=$(wait_job "$1" "$(jq -r .id <<<"$r")" "${4:-900}")
	[ "$(jq -r .state <<<"$j")" = ok ] || die "$2: $(jq -r .log <<<"$j" | tail -n 30)"
	echo "$j"
}

# backup GROUP -> logs the result; records the plugin domains seen in the VM meanwhile
backup() {
	local r j
	con run 'rm -f /run/nexus-lab-ps; setsid sh -c "for i in \$(seq 600); do ps -eo label,comm | grep -E \"nexus_plugin(host)?_t\" >>/run/nexus-lab-ps; sleep 0.2; done" </dev/null >/dev/null 2>&1 &' >/dev/null
	r=$(api admin POST /jobs "$(jq -nc --arg t "${TENANT:-plugins}" --argjson g "$1" '{kind:"backup", tenant:$t, params:{group_id:$g}}')")
	expect 202 "backup job"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 1800)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "backup: $(jq -r .log <<<"$j" | tail -n 30)"
	log "backup job $(jq -r .id <<<"$j") ok in $(jq '.finished - .started' <<<"$j") s: $(jq -c .result <<<"$j")"
	{ jq -r .log <<<"$j" | grep "not backed up" || true; } | while read -r l; do log "$l"; done
	jq -r .log <<<"$j" | sed -n 's/^.*not backed up: \(.*\): [^:]*$/\1/p' >"$S/skipped"
	log "domains during the backup: $(con run 'sort -u /run/nexus-lab-ps 2>/dev/null | sed "s/  */ /g"' | tr '\n' ';')"
}

install() {
	bundle
	apienv
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	local id r q st e
	id=$(jq -r .id "$MANIFEST")
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
}

plugin() {
	install
	local id kind r src pol grp j snap time ents paths want have
	id=$(jq -r .id "$MANIFEST")
	kind=$(jq -r '.kinds[0].kind' "$MANIFEST")
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

	# the snapshots table is refreshed on the scheduler's next tick
	for _ in $(seq 60); do
		snap=$(api admin GET '/snapshots?tenant=plugins' | jq -c '[.[] | select(.source | startswith("plugin-"))] | sort_by(.time)')
		[ "$(jq length <<<"$snap")" -ge 2 ] && break
		sleep 1
	done
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
	# minus the files the backup reported as "not backed up" (SELinux labels nexus_plugin_t
	# may not read, e.g. *.cgi docs are httpd_sys_script_exec_t)
	skip=$(sed "s|^$DATA/|./|; s|.*|! -path '&'|" "$S/skipped" | tr '\n' ' ')
	want=$(con run "cd '$DATA' && h=\$(find . -type f $skip -print0 | xargs -0r sha256sum | cut -d' ' -f1 | sort | sha256sum | cut -c1-16); echo \"\$h \$(find . -type f $skip | wc -l)\"" | tr -d '\r\n')
	[ "$have" = "$want" ] || die "download differs from $DATA in the VM: have $have, want $want"
	log "files_get: $(echo "$have" | cut -d' ' -f2) files, sha256 identical to $DATA in the VM"
}

check() {
	"$here/e2e.sh" check
	con run 'echo "== plugin units"; systemctl is-enabled nexus-plugin-install.path; systemctl show -p Result,ExecMainStatus nexus-plugin-install.service
echo "== install tree labels (bin/plugin must be nexus_plugin_exec_t)"; find /var/lib/nexus/plugins -maxdepth 4 -exec ls -dZ {} + | head -n 20
ls -Z /usr/libexec/nexus/nexus-pluginhost /usr/libexec/nexus/nexus-plugin-install /usr/bin/nexus-plugin
echo "== domains seen during backups"; sort -u /run/nexus-lab-ps 2>/dev/null | sed "s/  */ /g"' 120
	# expected: nexus_plugin_t denied on the files the backup reported as "not backed up"
	local n ok=''
	[ -s "$ROOT/run/api/skipped" ] && ok=$(sed 's/.*/scontext=system_u:system_r:nexus_plugin_t:s0 .*path="&"|path="&".*scontext=system_u:system_r:nexus_plugin_t:s0 /' "$ROOT/run/api/skipped" | paste -sd'|')
	local q="ausearch -m avc,user_avc,selinux_err -ts boot 2>/dev/null | grep -E 'context=[^ ]*nexus_' | grep -vE '${ok:-^$}'"
	n=$(con run "$q | wc -l" | tr -d '\r\n')
	con run "$q | tail -n 10" || true
	[ "$n" = 0 ] || die "$n AVC/SELinux error records with a nexus context since boot"
	con run 'grep -q nexus_pluginhost_t /run/nexus-lab-ps && grep -q nexus_plugin_t /run/nexus-lab-ps' >/dev/null ||
		log "WARN: nexus_pluginhost_t / nexus_plugin_t not observed (job too short for the 0.2 s poll?)"
	log "check: 0 nexus AVCs since boot"
}

# single sign-on against the Keycloak testbox (host 127.0.0.1, VM 10.0.2.2, both as kc.nexus-lab)
oidc() {
	local tb=$repo/crates/web-api/tests/oidc-testbox/run.sh r q j loc form u
	TLS=1 env -u PORT "$tb" start >/dev/null
	eval "$(TLS=1 env -u PORT "$tb" env)"
	local kport=${NEXUS_OIDC_ISSUER##*:}
	kport=${kport%%/*}
	con run "grep -q kc.nexus-lab /etc/hosts || echo '10.0.2.2 kc.nexus-lab' >>/etc/hosts" >/dev/null
	apienv
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	login so "$SO_PW" "$SO_TOTP"
	api admin POST /tenants '{"name":"sso"}' >/dev/null
	r=$(api admin PUT /settings/oidc "$(jq -nc --arg i "$NEXUS_OIDC_ISSUER" --arg c "$NEXUS_OIDC_CLIENT_ID" \
		--arg sct "$NEXUS_OIDC_CLIENT_SECRET" --arg ca "$(cat "$NEXUS_OIDC_CA")" \
		'{enabled:true, issuer:$i, client_id:$c, client_secret:$sct, ca_pem:$ca, scopes:["openid","profile","email"],
		  username_claim:"preferred_username", groups_claim:"groups", label:"Sign in with Keycloak",
		  mappings:[{group:"/nexus-admins", role:"admin", tenants:[]}, {group:"/acme-users", role:"tenant_user", tenants:["sso"]}]}')")
	case $(status) in
	202)
		q=$(jq -r .quorum_id <<<"$r")
		api so POST "/quorum/$q/approve" '{}' >/dev/null
		expect 200 "approve oidc.update"
		log "oidc settings saved via quorum #$q"
		;;
	200) log "oidc settings saved (approvals disabled)" ;;
	*) die "PUT /settings/oidc: HTTP $(status) $r" ;;
	esac
	# the scheduler adds the IdP to the egress allow-list on its next tick (≤ 30 s)
	for _ in $(seq 20); do
		r=$(api admin POST /settings/oidc/test '{}')
		expect 200 "oidc test"
		jq -e '[.[] | startswith("ok")] | all' <<<"$r" >/dev/null && break
		sleep 5
	done
	jq -e '[.[] | startswith("ok")] | all' <<<"$r" >/dev/null || die "oidc test from the appliance: $r"
	log "oidc test from the appliance: $(jq -c . <<<"$r")"
	# browser-less sign-in: appliance start -> Keycloak login form -> callback -> session
	local K=(curl -s --resolve "kc.nexus-lab:$kport:127.0.0.1" --cacert "$NEXUS_OIDC_CA")
	local A=(curl -s --resolve "nexus-m5:$PORT:127.0.0.1" --cacert "$ROOT/etc/nexus/tls/cert.pem")
	sso() { # USER PASSWORD -> prints the final appliance redirect location; session in $S/sso-$1.jar
		rm -f "$S/sso-$1.jar" "$S/kc-$1.jar"
		loc=$("${A[@]}" -c "$S/sso-$1.jar" -o /dev/null -w '%{redirect_url}' "$BASE/auth/oidc/start?next=/")
		[[ $loc == https://kc.nexus-lab:* ]] || die "oidc start for $1: redirect to '$loc'"
		form=$("${K[@]}" -c "$S/kc-$1.jar" "$loc" | grep -o 'action="[^"]*"' | head -n 1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')
		[ -n "$form" ] || die "no Keycloak login form for $1"
		loc=$("${K[@]}" -b "$S/kc-$1.jar" -c "$S/kc-$1.jar" -o /dev/null -w '%{redirect_url}' \
			--data-urlencode "username=$1" --data-urlencode "password=$2" --data-urlencode credentialId= "$form")
		[[ $loc == https://nexus-m5:$PORT/api/v1/auth/oidc/callback* ]] || die "Keycloak login of $1: redirect to '$loc'"
		"${A[@]}" -b "$S/sso-$1.jar" -c "$S/sso-$1.jar" -o /dev/null -w '%{redirect_url}' "$loc"
	}
	loc=$(sso kc-alice alice-testbox-pw)
	u=$("${A[@]}" -b "$S/sso-kc-alice.jar" "$BASE/auth/me")
	[ "$(jq -r '.name + " " + .role' <<<"$u")" = "kc-alice admin" ] || die "kc-alice after SSO ($loc): $u"
	log "kc-alice signed in via SSO: $(jq -c '{name, role, auth}' <<<"$u")"
	loc=$(sso kc-tina tina-testbox-pw)
	u=$("${A[@]}" -b "$S/sso-kc-tina.jar" "$BASE/auth/me")
	[ "$(jq -r '.name + " " + .role + " " + (.tenant // "")' <<<"$u")" = "kc-tina tenant_user sso" ] || die "kc-tina after SSO ($loc): $u"
	log "kc-tina signed in via SSO: $(jq -c '{name, role, tenant, auth}' <<<"$u")"
	loc=$(sso kc-nobody nobody-testbox-pw)
	[[ $loc == *"oidc_error=denied"* ]] || die "kc-nobody: want oidc_error=denied, got '$loc'"
	log "kc-nobody refused: $loc"
	r=$(api admin GET '/audit?limit=50')
	log "audit: $(jq -c '[.[] | select(.action | startswith("auth.oidc") or startswith("user.oidc")) | .action + " " + .actor] | .[:6]' <<<"$r")"
}

# PostgreSQL reference plugin against plugins/postgresql/testbox (QEMU user net: 10.0.2.2 = host)
pg() {
	[ "$PLUGIN" = postgresql ] || die "pg: run with PLUGIN=postgresql"
	local TENANT=pg
	install
	local tb=$repo/plugins/postgresql/testbox/run.sh src pol grp j snap time want have r
	env -u PORT "$tb" start >/dev/null # PORT is the appliance API port here
	eval "$(env -u PORT "$tb" env)"
	psql_tb() { podman exec -u postgres "$1" psql -v ON_ERROR_STOP=1 -qtAX -d "$2" -c "$3"; }
	psql_tb nexus-pg-testbox postgres 'DROP DATABASE IF EXISTS labdb WITH (FORCE)'
	psql_tb nexus-pg-testbox-alt postgres 'DROP DATABASE IF EXISTS labdb_copy WITH (FORCE)'
	psql_tb nexus-pg-testbox postgres 'CREATE DATABASE labdb'
	psql_tb nexus-pg-testbox labdb "CREATE TABLE t (id int PRIMARY KEY, v text, j jsonb);
		INSERT INTO t SELECT g, md5(g::text), jsonb_build_object('g', g) FROM generate_series(1, 20000) g;
		CREATE INDEX t_v ON t (v); CREATE VIEW tv AS SELECT id, v FROM t WHERE id % 2 = 0;"
	want=$(psql_tb nexus-pg-testbox labdb "SELECT md5(string_agg(t::text, ',' ORDER BY id)) FROM t")
	api admin POST /tenants '{"name":"pg"}' >/dev/null
	expect 201 "create tenant"
	src=$(api admin POST /sources "$(jq -nc --arg pw "$NEXUS_PG_PASSWORD" --arg sp "$NEXUS_PG_SUPER_PASSWORD" \
		--arg ca "$(cat "$NEXUS_PG_CA")" --argjson port "$NEXUS_PG_PORT" --argjson alt "$NEXUS_PG_ALT_PORT" \
		'{tenant:"pg", kind:"plugin:postgresql", name:"pg-lab", config:{host:"10.0.2.2", port:$port, user:"nexus",
		password:$pw, sslmode:"verify-full", ca_cert:$ca, restore_host:"10.0.2.2", restore_port:$alt,
		restore_user:"postgres", restore_password:$sp, databases_include:["labdb"]}}')" | jq -r .id)
	expect 201 "create postgresql source"
	j=$(job admin plugin_validate "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
	jq -e '.result.valid == true' <<<"$j" >/dev/null || die "plugin_validate: $(jq -c .result <<<"$j")"
	j=$(job admin plugin_guests "$(jq -nc --argjson s "$src" '{source_id:$s}')" 300)
	log "plugin_guests: $(jq -c '[.result.guests[].id]' <<<"$j")"
	pol=$(api admin POST /policies '{"name":"pg","schedule":"daily 04:44","gfs":{"daily":7,"weekly":0,"monthly":0,"yearly":0},"offsite":false}' | jq -r .id)
	expect 201 "create policy"
	grp=$(api admin POST /groups "$(jq -nc --argjson s "$src" --argjson p "$pol" \
		'{tenant:"pg", source_id:$s, policy_id:$p, name:"labdb", guests:["labdb"]}')" | jq -r .id)
	expect 201 "create group"
	backup "$grp"
	for _ in $(seq 60); do
		snap=$(api admin GET '/snapshots?tenant=pg' | jq -c '[.[] | select(.source | endswith("-labdb"))] | sort_by(.time)')
		[ "$(jq length <<<"$snap")" -ge 1 ] && break
		sleep 1
	done
	[ "$(jq length <<<"$snap")" -ge 1 ] || die "no labdb snapshot: $snap"
	time=$(jq -r '.[-1].time' <<<"$snap")
	snap=$(jq -r '.[-1].source' <<<"$snap")
	r=$(api admin POST /jobs "$(jq -nc --arg s "$snap" --argjson t "$time" \
		'{kind:"plugin_restore", tenant:"pg", params:{source:$s, time:$t, restore:"to_target", params:{database:"labdb_copy", server:"alternate"}}}')")
	expect 202 "plugin_restore"
	j=$(wait_job admin "$(jq -r .id <<<"$r")" 900)
	[ "$(jq -r .state <<<"$j")" = ok ] || die "plugin_restore: $(jq -r .log <<<"$j" | tail -n 30)"
	log "plugin_restore: $(jq -c .result <<<"$j")"
	have=$(psql_tb nexus-pg-testbox-alt labdb_copy "SELECT md5(string_agg(t::text, ',' ORDER BY id)) FROM t")
	[ "$have" = "$want" ] || die "restored table differs: $have != $want"
	[ "$(psql_tb nexus-pg-testbox-alt labdb_copy 'SELECT count(*) FROM tv')" = 10000 ] || die "view missing after restore"
	log "pg: labdb backed up and restored to the alternate server as labdb_copy, contents identical ($want)"
}

stop() { "$here/run.sh" stop; }

log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

[ $# -gt 0 ] || { sed -n '2,28p' "$0" >&2; exit 2; }
for step in "$@"; do
	case $step in
	image | bundle | install | disk | boot | setup | plugin | pg | oidc | check | stop) "$step" ;;
	*) sed -n '2,28p' "$0" >&2; exit 2 ;;
	esac
done
