# Disk encryption with LUKS2 and TPM, NVMe metadata tier: design (Phase 40, #22)

Status: proposal (2026-10-28), before any code. Written without the lab (no TPM run yet); the facts below come from
the tree. The decisions marked as proposed need the maintainer's review, as they decide what an attacker with the
hardware gets.

## What is protected today

- **Chunks** are AEAD-encrypted (XChaCha20-Poly1305) under tenant DEKs, which are wrapped by the appliance KEK.
- **The KEK** sits in clear in `/var/lib/nexus/keyd/kek.local` on the system disk (`crates/keyd/src/lib.rs`, `seal` /
  `unseal` are plain file writes), protected by file permissions and SELinux only (manual chapter 2, "Disk
  encryption"). `kek.recovery` is the KEK wrapped under the 24-word recovery key (ADR-015).
- **The catalog** (`/var/lib/nexus/catalog`: file index with path names, job history, audit log), the credentials
  of sources and targets, and the TLS keys are on the system disk in clear.
- **The installer** (`release/iso/config.toml`, Anaconda with bootc-image-builder) creates an unencrypted system
  disk; `os/slim.sh` removes cryptsetup, the TPM tools and clevis.

So whoever takes the system disk (stolen appliance, a disk sent back under warranty) gets the KEK and thereby every
backup, plus the file names and credentials. A stolen data array alone gives nothing readable. The order below
follows that risk.

## Decisions proposed

1. **M1: the KEK sealed to the TPM** (closes the main gap with the least change). `kek.local` becomes a systemd
   credential encrypted with the TPM only (`systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7`), loaded by the
   keyd unit through `LoadCredentialEncrypted=kek:/var/lib/nexus/keyd/kek.cred`; keyd reads
   `$CREDENTIALS_DIRECTORY/kek`. systemd (PID 1) talks to the TPM, keyd keeps `PrivateDevices=yes` and never opens
   `/dev/tpmrm0`; no TPM library in our code. The plan's "keyd is the only process with TPM access" becomes "only
   PID 1 and the enrolment helper". Without a TPM (or one that fails the self-test) the appliance keeps the clear
   file and the dashboard says so; the first-boot wizard shows which mode it chose.
2. **PCR 7 only** (Secure Boot state and its certificate databases). Not PCR 4/9/11: they change on every bootc
   update and every kernel, and a rollback would need the old values. PCR 7 changes when the firmware's db/dbx is
   updated or Secure Boot is turned off: the KEK then does not unseal, keyd stays down, the dashboard and the console
   say "enter the recovery key", and `nexusctl keys reseal` (recovery key, then a new credential) restores it. With
   Secure Boot off, PCR 7 still binds the credential to this TPM but not to a boot chain: shown as a warning.
   A future pcrlock / signed PCR 11 policy (when AlmaLinux ships UKIs for bootc) can replace this without a format
   change for the recovery path.
3. **M2: LUKS2 on the data array** (`md -> LUKS2 -> XFS`) for new arrays made by `nexus-disks create_array`: the
   volume key random, keyslot 0 a TPM2 token (`systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7`), keyslot 1 a
   passphrase derived from the KEK by keyd (HKDF-SHA256, label `nexus luks data v1`, given to the helper once through
   a one-shot request, never stored). So on new hardware the recovery key opens the KEK and the KEK opens the array.
   `/etc/crypttab` gets `nexus-data UUID=<luks uuid> none tpm2-device=auto,discard`; the mount unit points at
   `/dev/mapper/nexus-data`. Existing clear arrays stay as they are (no in-place encryption of a live store).
4. **M3: the system disk's `/var`** (catalog, credentials, keys) on LUKS2 from the installer: kickstart `autopart
   --encrypted` with a random one-time passphrase from a `%pre` script, then the first boot enrols the TPM2 token
   and the KEK-derived keyslot and wipes the install passphrase (`systemd-cryptenroll --wipe-slot=password`). Needs
   the unlock in the initrd (`systemd-cryptsetup` with the TPM2 token; dracut module `tpm2-tss`): the image keeps
   cryptsetup and tpm2-tss back from `os/slim.sh`. Lab first: Anaconda's behaviour with `ostreecontainer` and an
   encrypted autopart is not checked.
5. **M4: the NVMe metadata tier**: the catalog on an md RAID1 of two NVMe disks (role `metadata`, LUKS2 as in M2),
   only at setup before the first backup (same rule as the data array: no move of a live catalog, docs/hardware.md).
6. **Virtual appliances**: a vTPM is a file on the hypervisor (manual chapter 2); sealing still protects a copied
   disk without the vTPM state, not a copy of the whole VM. The wizard says this and offers the same modes.

## Updates, disks, hardware

- **bootc update or rollback**: PCR 7 is unchanged, nothing to do. greenboot's health check gets a "KEK unsealed"
  check, so an update that breaks the unseal is rolled back.
- **Firmware or dbx update changing PCR 7** (the BIOS setup, a vendor tool, or shim's dbx update through `dbxtool`,
  which the image keeps, `os/slim.sh`): sealing to the next PCR 7 value ahead of time needs pcrlock, so the recovery
  key is needed once after such a reboot (`nexusctl keys reseal`); documented in manual chapter 13.
- **Replaced data disk**: md rebuilds below LUKS, nothing to do. **New hardware** (system disk moved, mainboard
  replaced): the recovery key opens `kek.recovery`, keyd reseals to the new TPM, `nexus-disks` re-enrols the array's
  TPM2 token with the KEK-derived keyslot.

## Changes in the tree (when accepted)

- `os/slim.sh`: keep `cryptsetup` and `tpm2-tss` (systemd's TPM support loads `libtss2-*`); clevis, `tpm2-tools`
  and the FAPI stay removed.
- `crates/keyd`: `seal` / `unseal` for the credential mode, `reseal` with the recovery key; a test that the clear
  file is not written in TPM mode (security change: a line in `docs/security-review.md`).
- `nexus-keyd.service`: `LoadCredentialEncrypted=`; `os/selinux/nexus.te`: nothing for keyd (PID 1 decrypts).
- `nexus-disks`: LUKS2 in `create_array`, the crypttab line, the TPM2 token; parsers and fakes in
  `os/greenboot/tests/test_nexus_disks.py`.
- greenboot check, dashboard state, manual chapters 2, 13 and 14.

## Open questions

- Whether AlmaLinux 10's systemd builds `systemd-creds` with TPM2 support and which `tpm2-tss` packages that needs.
- Anaconda with `ostreecontainer` and `autopart --encrypted` (M3).
- How many appliances will run without Secure Boot (unsigned shim is not an option; the bootc image keeps
  AlmaLinux's signed shim and kernel).

## Lab plan

1. M1 on appliance VM 201 with swtpm (`lab/appliance/run.sh TPM=1`) and OVMF Secure Boot: seal, reboot, update,
   rollback, Secure Boot off (unseal refused, recovery key, reseal).
2. M2: `lab/appliance/disks.sh` with the encrypted array, member failure and rebuild, the array on new hardware.
3. M3 with the installer ISO (`lab/appliance/iso-test.sh`); M4 with `NVME=2`.
