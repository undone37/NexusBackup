# REST helpers shared by lab/e2e/m5-api.sh and lab/linux/e2e.sh (sourced).
# Needs: ROOT (cert in $ROOT/etc/nexus/tls/cert.pem), PORT, S (state dir: cookie
# jars, CSRF tokens, last TOTP codes). curl verifies the appliance certificate
# for the name nexus-m5.
api_lib=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=https://nexus-m5:$PORT/api/v1
T0=${T0:-$(date +%s)}

log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }
die() {
	log "FAIL: $*"
	exit 1
}

# api USER METHOD PATH [JSON] -> body on stdout, HTTP status in $S/status
api() {
	local u=$1 m=$2 p=$3 d=${4:-}
	local args=(-s --cacert "$ROOT/etc/nexus/tls/cert.pem" --resolve "nexus-m5:$PORT:127.0.0.1"
		-b "$S/$u.jar" -c "$S/$u.jar" -X "$m" -o "$S/body" -w '%{http_code}')
	[ "$m" = GET ] || args+=(-H "X-CSRF-Token: $(cat "$S/$u.csrf" 2>/dev/null)")
	[ -z "$d" ] || args+=(-H 'Content-Type: application/json' --data-binary "$d")
	curl "${args[@]}" "$BASE$p" >"$S/status"
	cat "$S/body"
}
status() { cat "$S/status"; }
expect() { [ "$(status)" = "$1" ] || die "$2: HTTP $(status) $(cat "$S/body")"; }

# login USER PASSWORD TOTP_SECRET (waits for a fresh TOTP step: codes are single-use)
login() {
	local u=$1 pw=$2 sec=$3 code
	# per appliance, not per script: the web-api refuses a TOTP code reused by any client
	local last=${ROOT:-$S}/run/lastcode-$u
	mkdir -p "${last%/*}"
	code=$(python3 "$api_lib/totp.py" "$sec")
	if [ -f "$last" ] && [ "$(cat "$last")" = "$code" ]; then
		sleep $((30 - $(date +%s) % 30 + 1))
		code=$(python3 "$api_lib/totp.py" "$sec")
	fi
	echo "$code" >"$last"
	rm -f "$S/$u.jar"
	api "$u" POST /auth/login "$(jq -nc --arg n "$u" --arg p "$pw" --arg t "$code" '{name:$n,password:$p,totp:$t}')" |
		jq -r .csrf >"$S/$u.csrf"
	expect 200 "login $u"
	log "logged in as $u"
}

# wait_job USER ID [timeout s] -> final job JSON
wait_job() {
	local u=$1 id=$2 to=${3:-900} j st
	for _ in $(seq "$to"); do
		j=$(api "$u" GET "/jobs/$id")
		st=$(jq -r .state <<<"$j")
		case $st in ok | failed | cancelled)
			echo "$j"
			return
			;;
		esac
		sleep 1
	done
	die "job $id still $st after ${to}s"
}
