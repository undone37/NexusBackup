#!/usr/bin/env bash
# Registers an Entra ID app for the NexusBackup Microsoft 365 plugin (docs/m365.md
# "Entra ID setup") with the Azure CLI: app registration, self-signed certificate
# (or your own), the Microsoft Graph application permissions the plugin needs and
# admin consent. Prints the values for the source form.
#
# Run it on an admin workstation (Azure CLI `az`, `openssl`), signed in with
# `az login --tenant <tenant>` as a Global Administrator or Privileged Role
# Administrator. Never on the appliance: the appliance has no outbound access to
# these APIs and must not hold admin credentials.
#
# Usage: register-app.sh [--name NAME] [--out DIR] [--days N]
#                        [--cert FILE --key FILE] [--backup-only]
#                        [--teams-messages] [--chats]
#   --backup-only     read permissions only (no restores into Microsoft 365)
#   --teams-messages  ChannelMessage.Read.All (protected API: Microsoft must approve)
#   --chats           Chat.Read.All + Chat.ReadBasic.All (protected, metered API)
#   Several apps (source field "Further app registrations"): run it once per app
#   with different names.
set -euo pipefail

GRAPH=00000003-0000-0000-c000-000000000000
name="NexusBackup M365"
out=""
days=730
cert=""
key=""
backup_only=0
teams_messages=0
chats=0

die() {
	echo "register-app: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--name) name="${2:?}"; shift 2 ;;
	--out) out="${2:?}"; shift 2 ;;
	--days) days="${2:?}"; shift 2 ;;
	--cert) cert="${2:?}"; shift 2 ;;
	--key) key="${2:?}"; shift 2 ;;
	--backup-only) backup_only=1; shift ;;
	--teams-messages) teams_messages=1; shift ;;
	--chats) chats=1; shift ;;
	-h | --help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown option $1 (--help)" ;;
	esac
done

command -v az >/dev/null || die "the Azure CLI (az) is required"
command -v openssl >/dev/null || die "openssl is required"
if [ -n "$cert$key" ] && { [ -z "$cert" ] || [ -z "$key" ]; }; then
	die "--cert and --key go together"
fi

# Application permissions (docs/m365.md, "API permissions")
if [ "$backup_only" = 1 ]; then
	perms=(User.Read.All Mail.Read Calendars.Read Contacts.Read Sites.Read.All Files.Read.All
		Team.ReadBasic.All Channel.ReadBasic.All)
else
	perms=(User.Read.All Mail.ReadWrite Calendars.ReadWrite Contacts.ReadWrite Sites.ReadWrite.All
		Files.ReadWrite.All Team.ReadBasic.All Channel.ReadBasic.All)
fi
if [ "$teams_messages" = 1 ]; then
	perms+=(ChannelMessage.Read.All)
	[ "$backup_only" = 1 ] || perms+=(Teamwork.Migrate.All Channel.Create)
fi
[ "$chats" = 1 ] && perms+=(Chat.Read.All Chat.ReadBasic.All)

tenant=$(az account show --query tenantId -o tsv) || die "not signed in: az login --tenant <tenant> --allow-no-subscriptions"

umask 077
[ -n "$out" ] || out="./nexus-m365-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"
if [ -z "$cert" ]; then
	cert="$out/app.crt"
	key="$out/app.key"
	openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$days" \
		-subj "/CN=$name" -keyout "$key" -out "$cert" 2>/dev/null
fi
openssl x509 -in "$cert" -noout >/dev/null 2>&1 || die "$cert: not a PEM certificate"
openssl pkey -in "$key" -noout -passin pass: >/dev/null 2>&1 || die "$key: not an unencrypted PEM key"
cat "$cert" "$key" >"$out/app.pem"
thumb=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')

echo "Creating the app registration \"$name\" in tenant $tenant ..."
app=$(az ad app create --display-name "$name" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad app credential reset --id "$app" --cert "@$cert" --append --only-show-errors >/dev/null
az ad sp create --id "$app" --only-show-errors >/dev/null

echo "Granting ${#perms[@]} Microsoft Graph application permissions ..."
args=()
for p in "${perms[@]}"; do
	id=$(az ad sp show --id "$GRAPH" --query "appRoles[?value=='$p'].id | [0]" -o tsv)
	[ -n "$id" ] || die "Microsoft Graph has no application permission $p"
	args+=("$id=Role")
done
az ad app permission add --id "$app" --api "$GRAPH" --api-permissions "${args[@]}" --only-show-errors >/dev/null
# the new service principal takes a moment to replicate
for i in 1 2 3 4 5 6; do
	if az ad app permission admin-consent --id "$app" --only-show-errors >/dev/null 2>&1; then
		break
	fi
	[ "$i" = 6 ] && die "admin consent failed: grant it in the Entra admin center (App registrations → $name → API permissions)"
	sleep 10
done

# shellcheck disable=SC2016 # `$select` is OData, not a shell variable
sp_host=$(az rest --method GET --url 'https://graph.microsoft.com/v1.0/sites/root?$select=siteCollection' \
	--query siteCollection.hostname -o tsv 2>/dev/null || true)

cat <<EOF

Done. Values for the source (Configuration → Sources → Microsoft 365 tenant):

  Tenant ID ............ $tenant
  Client ID ............ $app
  Certificate .......... $cert
  Private key .......... $key
  (both in one file, for "Further app registrations": $out/app.pem)
  SharePoint host ...... ${sp_host:-<tenant>.sharepoint.com (look it up in the SharePoint admin center)}
  OneDrive host ........ ${sp_host:+${sp_host%%.*}-my.${sp_host#*.}}
  Thumbprint (SHA-1) ... $thumb  (validation logs it)

Permissions: ${perms[*]}
EOF
if [ "$teams_messages" = 1 ] || [ "$chats" = 1 ]; then
	echo "Protected APIs: request access at https://aka.ms/teamsgraph/requestaccess (model B also needs an Azure subscription linked to the app)."
fi
echo "Paste the certificate and key into the source, then delete $out (the appliance keeps them sealed)."
