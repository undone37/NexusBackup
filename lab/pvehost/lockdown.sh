#!/usr/bin/env bash
# Tenant lockdown with a signed-in tenant administrator, and the new-device notice (#69, plan.md Phase 39 L9), on the
# appliance VM through the tunnel of deploy.sh, in a tenant of its own ($TENANT, nothing else in it):
#
#   lockdown.sh account   tenant $TENANT and its administrator "$USER_NAME" (activation code, own password and
#                         authenticator, an e-mail address for sign-in notices); first sign-in (the device baseline)
#   lockdown.sh device    a sign-in with another browser identification: alert login_new_device for the account
#   lockdown.sh enter     the security officer locks the tenant down (no hold: the tenant has no snapshots); the
#                         administrator's session ends at once and a new sign-in is refused
#   lockdown.sh lift      the administrator requests the lift, the security officer approves it; sign-in works again
#
# env: as vmware-e2e.sh (LAB, PORT); TENANT (ld-lab), USER_NAME (ld-admin), MAIL (ld-admin@lab.local)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export LAB=${LAB:-$HOME/nexus-lab/pvehost}
export PORT=${PORT:-28444}
TENANT=${TENANT:-ld-lab}
USER_NAME=${USER_NAME:-ld-admin}
MAIL=${MAIL:-ld-admin@lab.local}
ROOT=$LAB/appliance/root
S=$ROOT/run/api
mkdir -p "$S"
# shellcheck disable=SC1091
. "$ROOT/secrets.env"
# shellcheck source=lab/e2e/api-lib.sh
. "$repo/lab/e2e/api-lib.sh"
api_lib=$repo/lab/e2e
ENV=$S/$USER_NAME.env

tadmin_login() { # tadmin_login [user agent]: a session of the tenant administrator
	# shellcheck disable=SC1090
	. "$ENV"
	local code
	code=$(fresh_code "$USER_NAME" "$TA_TOTP")
	rm -f "$S/$USER_NAME.jar"
	curl -s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1" -c "$S/$USER_NAME.jar" \
		-A "${1:-curl/lab}" -H 'Content-Type: application/json' -o "$S/body" -w '%{http_code}' \
		--data-binary "$(jq -nc --arg n "$USER_NAME" --arg p "$TA_PW" --arg t "$code" '{name:$n,password:$p,totp:$t}')" \
		"$BASE/auth/login" >"$S/status"
	jq -r '.csrf // empty' "$S/body" >"$S/$USER_NAME.csrf" 2>/dev/null || true
}

step_account() {
	local r code pw sec
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin GET /tenants | jq -e --arg t "$TENANT" '.[] | select(.name == $t)' >/dev/null ||
		{ api admin POST /tenants "$(jq -nc --arg t "$TENANT" '{name:$t}')" >/dev/null && expect 201 "tenant $TENANT"; }
	if [ ! -f "$ENV" ]; then
		pw="ld-$(head -c 12 /dev/urandom | base64 | tr -d '/+=')"
		r=$(api admin POST /users "$(jq -nc --arg n "$USER_NAME" --arg t "$TENANT" '{name:$n, role:"tenant_admin", tenant:$t}')")
		expect 201 "create $USER_NAME"
		code=$(jq -r '.activation.code' <<<"$r")
		r=$(api anon POST /auth/activate/begin "$(jq -nc --arg n "$USER_NAME" --arg c "$code" '{name:$n, code:$c}')")
		expect 200 "activation begin"
		sec=$(jq -r '.totp_secret' <<<"$r")
		api anon POST /auth/activate/complete "$(jq -nc --arg n "$USER_NAME" --arg c "$code" --arg p "$pw" \
			--arg t "$(python3 "$api_lib/totp.py" "$sec")" '{name:$n, code:$c, password:$p, totp:$t}')" >/dev/null
		expect 200 "activation complete"
		python3 "$api_lib/totp.py" "$sec" >"$ROOT/run/lastcode-$USER_NAME"
		(umask 077 && printf "TA_PW='%s'\nTA_TOTP='%s'\n" "$pw" "$sec" >"$ENV")
	fi
	tadmin_login
	expect 200 "first sign-in of $USER_NAME"
	api "$USER_NAME" PUT /auth/email "$(jq -nc --arg m "$MAIL" '{email:$m}')" >/dev/null
	expect 200 "e-mail for sign-in notices"
	log "tenant $TENANT, administrator $USER_NAME signed in (device baseline), notices to $MAIL"
}

step_device() {
	local a
	tadmin_login "${NEW_UA:-Mozilla/5.0 (X11; Linux x86_64) NexusLab-NewDevice/1.0}"
	expect 200 "sign-in from a new device"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	for _ in $(seq 12); do
		a=$(api admin GET /alerts | jq -c --arg u "$USER_NAME" '[.[] | select(.kind == "login_new_device" and ((.message // "") | contains($u)))][0] // empty')
		[ -n "$a" ] && break
		sleep 5
	done
	[ -n "$a" ] || die "no login_new_device alert for $USER_NAME"
	log "alert: $(jq -c '{kind, severity, message, delivery: (.delivery // .mail // .notified // null)}' <<<"$a" | cut -c1-400)"
}

step_enter() {
	local code
	tadmin_login
	expect 200 "sign-in before the lockdown"
	api "$USER_NAME" GET /auth/me >/dev/null
	expect 200 "session works"
	login so "$SO_PW" "$SO_TOTP"
	code=$(fresh_code so "$SO_TOTP")
	api so POST "/tenants/$TENANT/lockdown" "$(jq -nc --arg p "$SO_PW" --arg t "$code" \
		'{reason:"lab: lockdown.sh", hold:null, current_password:$p, current_totp:$t}')" >/dev/null
	[ "$(status)" = 200 ] || [ "$(status)" = 201 ] || die "lockdown: HTTP $(status) $(cat "$S/body")"
	log "tenant $TENANT locked down by the security officer"
	api "$USER_NAME" GET /auth/me >/dev/null
	[ "$(status)" = 401 ] || die "the administrator's session still works (HTTP $(status))"
	tadmin_login
	[ "$(status)" != 200 ] || die "the administrator can sign in during the lockdown"
	log "session ended at once (401), new sign-in refused (HTTP $(status): $(head -c 150 "$S/body"))"
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	api admin GET /alerts | jq -e --arg t "$TENANT" '[.[] | select(.kind == "tenant_lockdown")] | length > 0' >/dev/null ||
		die "no tenant_lockdown alert"
	log "alert tenant_lockdown raised"
}

step_lift() {
	local r q
	login admin "$ADMIN_PW" "$ADMIN_TOTP"
	r=$(api admin POST "/tenants/$TENANT/lockdown/lift" '{}')
	q=$(jq -r '.quorum_id // empty' <<<"$r")
	[ -n "$q" ] || die "lift: no approval request: HTTP $(status) $r"
	login so "$SO_PW" "$SO_TOTP"
	api so POST "/quorum/$q/approve" '{}' >/dev/null
	expect 200 "approve tenant.lockdown.lift"
	tadmin_login
	expect 200 "sign-in after the lift"
	log "lift requested by the appliance administrator, approved by the security officer; $USER_NAME signs in again"
}

for s in "${@:-account device enter lift}"; do
	for x in $s; do
		log "== $x"
		"step_$x"
	done
done
