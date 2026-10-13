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
# TLS=1 (appliance VM lab, lab/appliance/plugins.sh oidc): HTTPS on 127.0.0.1:$PORT (default 18444) with a lab CA
# (target/oidc-testbox/ca.crt) and the name kc.nexus-lab (host: --resolve to 127.0.0.1; VM: 10.0.2.2).
# Test-only credentials (realm.json); nothing here is used outside the testbox.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
KC=${KC:-26.4.0}
IMG=quay.io/keycloak/keycloak:$KC
NAME=nexus-oidc-testbox
if [ "${TLS:-0}" = 1 ]; then
	PORT=${PORT:-18444}
	KCHOST=kc.nexus-lab
	ISSUER=https://$KCHOST:$PORT/realms/nexus
	dir=$here/../../../../target/oidc-testbox
	CURL=(curl --resolve "$KCHOST:$PORT:127.0.0.1" --cacert "$dir/ca.crt")
else
	PORT=${PORT:-18080}
	ISSUER=http://127.0.0.1:$PORT/realms/nexus
	CURL=(curl)
fi

# lab CA + server certificate for kc.nexus-lab (TLS=1)
certs() {
	mkdir -p "$dir"
	[ -f "$dir/ca.crt" ] && return 0
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
		-subj /CN=oidc-testbox-ca -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$KCHOST" \
		-keyout "$dir/tls.key" -out "$dir/tls.csr" 2>/dev/null
	openssl x509 -req -in "$dir/tls.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial -days 3650 \
		-extfile <(echo "subjectAltName=DNS:$KCHOST") -out "$dir/tls.crt" 2>/dev/null
	chmod 0644 "$dir/tls.key" # read by the container's user (lab-only key)
}

ready() {
	for _ in $(seq 240); do
		"${CURL[@]}" -fsS -o /dev/null "$ISSUER/.well-known/openid-configuration" 2>/dev/null && return 0
		sleep 0.5
	done
	echo "run.sh: Keycloak did not come up; podman logs $NAME:" >&2
	podman logs "$NAME" 2>&1 | tail -40 >&2 || true
	return 1
}

case ${1:-} in
start)
	if "${CURL[@]}" -fsS -o /dev/null "$ISSUER/.well-known/openid-configuration" 2>/dev/null; then
		echo "oidc-testbox already up: $ISSUER"
		exit 0
	fi
	podman image exists "$IMG" || podman pull -q "$IMG" >/dev/null
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	# a run killed while creating (CI cancel) leaves a storage-only container podman rm -f does not see
	podman rm --storage "$NAME" >/dev/null 2>&1 || true
	if [ "${TLS:-0}" = 1 ]; then
		certs
		podman run -d --name "$NAME" -p "127.0.0.1:$PORT:8443" \
			-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=testbox-admin \
			-v "$here/realm.json:/opt/keycloak/data/import/realm.json:ro,Z" -v "$dir:/certs:ro,Z" \
			"$IMG" start-dev --import-realm --https-port=8443 --http-enabled=false \
			--https-certificate-file=/certs/tls.crt --https-certificate-key-file=/certs/tls.key \
			--hostname="https://$KCHOST:$PORT" >/dev/null
	else
		podman run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" \
			-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=testbox-admin \
			-v "$here/realm.json:/opt/keycloak/data/import/realm.json:ro,Z" \
			"$IMG" start-dev --import-realm --http-port=8080 --hostname="http://127.0.0.1:$PORT" >/dev/null
	fi
	ready
	echo "oidc-testbox up: Keycloak $KC, issuer $ISSUER"
	;;
stop) podman rm -f "$NAME" >/dev/null 2>&1 || true ;;
env)
	cat <<-EOF
		export NEXUS_OIDC_ISSUER=$ISSUER
		export NEXUS_OIDC_CLIENT_ID=nexusbackup
		export NEXUS_OIDC_CLIENT_SECRET=nexus-testbox-client-secret
		export NEXUS_OIDC_CA=${dir:-}/ca.crt
	EOF
	;;
*)
	sed -n '2,11p' "$0" >&2
	exit 2
	;;
esac
