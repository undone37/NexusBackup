# Security policy

NexusBackup is an **alpha**: it has had an internal security review ([docs/security-review.md](docs/security-review.md))
but no external audit or penetration test. Do not rely on it to protect production data.

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/undone37/NexusBackup/security/advisories/new), not in public
issues, pull requests or discussions. Include the version, the affected component and steps to reproduce.

You get an answer within 7 days. Fixes go into the next release; there are no backports to older releases while the
project is an alpha.

## Scope

In scope: the appliance image, its services and web UI/API, the agents, the Proxmox VE plugin, the plugins in
`plugins/`, the release and update chain (signatures, update policy).

Known and accepted gaps are listed in [docs/security-review.md](docs/security-review.md) (for example the key-encryption
key is not TPM-sealed yet); reports about them are still welcome if you find a practical attack path.

## Verifying releases

Images, packages and ISOs are signed with the release key in `release/keys/`; see [docs/release.md](docs/release.md)
and `release/verify.sh`.
