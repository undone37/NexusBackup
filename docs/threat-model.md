# Threat Model (v0.1)

Scope: the appliance, its sources and the offsite tier, as described in `plan.md`.

## Assets
1. Backup data and indexes (confidentiality, integrity, availability).
2. Tenant DEKs, appliance KEK, recovery key.
3. Credentials the appliance holds for sources and Storage Boxes (tier-0).
4. Retention guarantees (locks, compliance clock, audit log).

## Adversaries and mitigations

| # | Adversary / scenario | Goal | Mitigations | Residual risk |
|---|---|---|---|---|
| T1 | Ransomware on a source (PVE node, server) | Destroy or encrypt backups | Pull model: sources hold no appliance credentials and the appliance has no inbound data port; SSH `restrict`/forced command/`permitopen`. | Encrypted data gets backed up; detect via change-rate anomaly alerts (later). |
| T2 | Compromised admin account | Delete backups, shorten retention | Locks only extendable (storage layer, `extend_lock`/`delete_snapshot`); quorum for destructive actions and GC > 20 %; MFA; hash-chained audit log to SIEM. | Two colluding roles. |
| T3 | System time manipulation (`date`, rogue NTP) | Expire locks early | Compliance clock with bounded forward slew (ADR-011); NTS for chrony. | +1 % drift; root edit of the clock file (SELinux; TPM NV counter later). |
| T4 | Storage provider / Storage Box compromise | Read or fingerprint data | Per-tenant keyed chunk IDs, AEAD on everything, meaningless file names. | Traffic and size analysis. |
| T5 | Storage Box deletion (by a compromised appliance) | Destroy the offsite copy | Box snapshots set up in the Hetzner console (no API key on the appliance); offsite inventory monitoring. | ~6-week detection window. |
| T6 | Compromised appliance (root) | Reach the whole infrastructure | Least-privilege source credentials, separate management network, SELinux domains, no interactive root, nftables egress allow-list. | Source data readable within scope; this is inherent to the pull model. |
| T7 | Disk / hardware theft | Read data | LUKS2 sealed to TPM + Secure Boot; chunk AEAD as a second layer. | Cold-boot attack on a running system. |
| T8 | Bit rot / tampered chunks | Silent corruption | AEAD tag + keyed-hash re-check on every read; rolling verify; offsite sampled verify. | Corruption is detected, not repaired, without a second copy. |
| T9 | Crash / power loss during a write | Corrupt store | Commit protocol (ADR-012), GC aborts on an unreadable manifest/index, grace period. | Backups longer than the grace period. |
| T10 | Malicious agent / NBD / SFTP peer | Exploit parsers | Rust, fuzzing of network parsers, mTLS for agents, restore micro-VM for foreign file systems. | Kernel NBD/FS bugs (confined to the micro-VM). |
| T11 | Path traversal via source / index names | Write outside the store | `check_name` allows only `[A-Za-z0-9._-]` without a leading dot. | — |

## Open items
- Key handling in `keyd` (TPM sealing, memory locking, process isolation) — not implemented yet.
- Insider at the hosting provider combined with an appliance compromise.
