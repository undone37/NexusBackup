#!/usr/bin/env bash
# Keycloak testbox in rootless podman, for crates/web-api/tests/oidc_keycloak.rs.
#   run.sh start   start Keycloak (dev mode, realm `nexus` from realm.json: client `nexusbackup`
#                  with secret + PKCE S256, users kc-alice / kc-tina / kc-nobody in groups
#                  nexus-admins / acme-users / unrelated, group claim `groups`) on 127.0.0.1:$PORT
#                  and wait until the realm's discovery document answers
#   run.sh stop    remove the container (the realm goes with it)
#   run.sh env     print `export NEXUS_OIDC_*=...` lines
# The test starts the testbox itself when podman is available (NEXUS_OIDC_TESTBOX=skip
# disables it). env: KC (image tag, default 26.4.0), PORT (18080).
# Test-only credentials (realm.json); nothing here is used outside the testbox.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
KC=${KC:-26.4.0}
PORT=${PORT:-18080}
IMG=quay.io/keycloak/keycloak:$KC
NAME=nexus-oidc-testbox
ISSUER=http://127.0.0.1:$PORT/realms/nexus

ready() {
	for _ in $(seq 240); do
		curl -fsS -o /dev/null "$ISSUER/.well-known/openid-configuration" 2>/dev/null && return 0
		sleep 0.5
	done
	echo "run.sh: Keycloak did not come up; podman logs $NAME:" >&2
	podman logs "$NAME" 2>&1 | tail -40 >&2 || true
	return 1
}

case ${1:-} in
start)
	if curl -fsS -o /dev/null "$ISSUER/.well-known/openid-configuration" 2>/dev/null; then
		echo "oidc-testbox already up: $ISSUER"
		exit 0
	fi
	podman image exists "$IMG" || podman pull -q "$IMG" >/dev/null
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	podman run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=testbox-admin \
		-v "$here/realm.json:/opt/keycloak/data/import/realm.json:ro,Z" \
		"$IMG" start-dev --import-realm --http-port=8080 --hostname="http://127.0.0.1:$PORT" >/dev/null
	ready
	echo "oidc-testbox up: Keycloak $KC, issuer $ISSUER"
	;;
stop) podman rm -f "$NAME" >/dev/null 2>&1 || true ;;
env)
	cat <<-EOF
		export NEXUS_OIDC_ISSUER=$ISSUER
		export NEXUS_OIDC_CLIENT_ID=nexusbackup
		export NEXUS_OIDC_CLIENT_SECRET=nexus-testbox-client-secret
	EOF
	;;
*)
	sed -n '2,11p' "$0" >&2
	exit 2
	;;
esac
