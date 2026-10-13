# 13 Updates and rollback

This chapter is for **administrators**. It covers the appliance OS image, the backup agents and plugins.

## How appliance updates work

The appliance is an image-based system (bootc). An update replaces the whole read-only system image; your data in
`/var` and the configuration in `/etc` stay. The appliance keeps the previous image and can boot back into it.

1. The project builds a release image and the release manager **signs** it with an offline cosign key.
2. The appliance checks the release channel (`ghcr.io/undone37/nexusbackup:stable`) once a day.
3. A new image is **downloaded and staged only**. An unplanned reboot or power loss does not apply it; if a staged
   download is lost, the appliance downloads it again on the next check.
4. The staged image is applied (reboot) in the **maintenance window**, by default Sunday 03:00–05:00 UTC, or when an
   administrator requests it (**Install now** under **Settings → Updates**, or on the console).
5. After the reboot a health check runs. If it fails three boots in a row, the appliance **rolls back** to the
   previous image automatically.

The update agent (`nexus-update`) runs every 15 minutes. For the download it opens the firewall for the registry
hosts (`ghcr.io`, `pkg-containers.githubusercontent.com`, TCP 443) and closes it again afterwards.

> **Status:** The **Updates** tab in the web interface (below) shows the status and offers **Check now** and
> **Install now**; it was tested against the demo backend, and its appliance-side part is still being integrated.
> Rollback and the maintenance window are set on the local console as root (see the console-access gap in
> [02 Installation](02-installation.md#known-gaps-after-installation)); without action the appliance applies staged
> updates in the maintenance window on its own. The signing chain, unsigned-image rejection,
> staged-only download, apply on request and automatic rollback were tested in a lab VM with a local registry and
> the TEST key. The maintenance window, the scheduler's "do not reboot while jobs run" signal and the downgrade
> guard are covered by unit tests only. No real release has been published or signed yet. The pre-update checks are
> covered by unit tests; their run on a real appliance (SELinux confinement of the check tool) is not lab-tested yet.

## What the appliance accepts

The appliance accepts an OS image only if it comes from its configured repository **and** carries a valid cosign
signature, made with a pinned project key, over that exact image digest. Unsigned images, images signed with another
key, and images from other registries are rejected. There is no online transparency-log or certificate-authority
check: the key is pinned in the image (`/etc/pki/nexus/cosign/`).

- **No downgrade:** the appliance refuses to apply an image with a lower version than the running one, unless an
  administrator forces it with an explicit `apply`.
- **No retry of a failed update:** an image that was rolled back is remembered and not applied again automatically.
  It waits for a fixed release.

## Updates in the web interface

Open **Configuration → Settings → Updates**. Administrators, security officers and operators see the status; only
administrators see the buttons.

![Settings: Updates with an available update](images/settings-updates.png)

| Line | Meaning |
|---|---|
| status chip | **Up to date**, **Update available**, **Checking…**, **Staged**, **Blocked by checks** (the failed pre-update checks are listed above the box, see below) or **Error** (the error text is shown above the box) |
| **Running version** | the booted image: version, digest and since when it runs |
| **Staged, boots next** | an image that is downloaded and verified and boots at the next reboot; "none" if there is none |
| **Available** | a newer signed image in the channel, or "No newer image available." |
| **Rollback image** | the previous image the appliance can boot back into |
| **Channel** | the release channel, e.g. `stable` |
| **Maintenance window** | when staged updates are applied, e.g. "Sun 03:00, 120 min" (UTC) |
| **Last check** | when the appliance last looked for a new image |

- **Check now** looks for a new image immediately instead of waiting for the next scheduled check. The status shows
  **Checking…** until it is done.
- **Install now** (shown when an update is available and nothing is staged yet) installs the available version now
  instead of waiting for the maintenance window: after you confirm, the appliance stages it and reboots into it. With
  approvals enabled this is an approval request (`update apply`) that another administrator or security officer must
  approve first. The same rules as for `nexus-update apply` below apply: make sure no restore is running.

The web interface does not change the maintenance window and has no rollback button; use the console commands below.

<a id="pre-update-checks"></a>
## Private image repository

While the image repository is private (as during the 0.x test releases), the appliance needs a read-only pull
credential to download updates. Under **Settings → Updates → Registry credential** an administrator enters a user
name and a token; for GitHub (`ghcr.io`) that is a personal access token with only the `read:packages` scope. The
token is write-only: the page shows only the user name afterwards.

The appliance writes the credential into the update control directory (mode 0600). `nexus-update` turns it into
bootc's login file `/run/ostree/auth.json` (memory only) just for the download and deletes that file afterwards;
signature verification is unchanged. **Remove** deletes the credential. Both actions are audited
(`update.registry_auth`, `update.registry_auth_removed`).

## Pre-update checks

Before the appliance downloads an update, and again before it reboots into one, it runs the self-checks of
**Settings → Diagnostics** ([15 Troubleshooting](15-troubleshooting-faq.md#diagnostics-and-support-bundles)): disk
space, time synchronisation, firewall, key daemon, web certificate, audit log, catalog, SELinux, failed services and
the OS image. If a check of severity **error** or **critical** fails, the update is **not** downloaded or installed:

- **Settings → Updates** shows **Blocked by checks** and lists the failed checks, each linked to its entry in chapter 15;
- `nexus-update status` shows the result `refused: pre-update checks failed: …`;
- warnings (for example a certificate that expires within 30 days) do not stop an update.

Fix the causes, then click **Check now** (or wait for the next daily check). Rolling back is never blocked. If the
check tool itself cannot run, the update goes ahead, so that a broken check cannot block the update that fixes it.

## Check the update status on the console

On the local console, as root:

```sh
nexus-update status
```

It shows the booted, staged and rollback images (digest, version, signature mode), the channel, the maintenance
window, whether jobs currently postpone an update, the last check and its result, and any digests that failed.

## Update now

```sh
nexus-update stage     # check for a new image and download it now (not applied)
nexus-update apply     # reboot into the staged image now (ignores the window)
```

Both run the pre-update checks first and stop with `pre-update checks failed: …` if one fails. Only if support asks
you to: `NEXUS_UPDATE_DIAG=off nexus-update apply` skips them.

`apply` also applies an older version or a previously rolled-back image. Use it deliberately.

Before you apply: make sure no restore is running, and note the time. The web UI is unavailable while the appliance
reboots; scheduled jobs that were due during the reboot run once afterwards.

## Change the maintenance window

The default window is in `/etc/nexus/update.conf` (`NEXUS_UPDATE_WINDOW=Sun 03:00 120`, UTC, duration in minutes).
It can be overridden by writing one line into `/var/lib/nexus/update/window`:

```sh
echo "Sat 02:00 180" > /var/lib/nexus/update/window   # Saturdays 02:00–05:00 UTC
echo "daily 04:00 60" > /var/lib/nexus/update/window  # every day
echo off > /var/lib/nexus/update/window                # never apply automatically, only on "apply"
```

An invalid line falls back to the default window (and is logged).

## Roll back

**Settings → Updates** shows the **Rollback image**, i.e. the image a rollback boots into. Automatic rollback happens when the health check fails after an update. The check (`nexus-health`, run by greenboot)
requires:

- enough free disk space on `/var/lib/nexus`, `/var` and `/boot`;
- the services key service, web API and scheduler running;
- the web API answering `https://127.0.0.1:8443/health`;
- the catalog passing an integrity check and a full verification of the audit hash chain.

To go back manually to the previous image:

```sh
nexus-update rollback    # bootc rollback + reboot
```

Look at the health check log if an update was rolled back:

```sh
journalctl -u greenboot-healthcheck
```

> **Note:** If the health check fails for a reason an update cannot fix (full disk, damaged catalog), the appliance
> reboots up to three times and then rolls back, and the old image stays red as well. Fix the cause, then check the
> log above.

Releases keep the catalog backward compatible for one release, so a rollback to the previous image can still open it.
Do not skip back more than one release.

## Agent updates

Linux and Windows agents update themselves from signed releases the appliance sends to them.

1. Open **Agents**.
2. Click **Update agent** next to an enrolled agent and confirm.
3. The job page opens. The agent checks the release signature against its pinned release keys, refuses a version
   that is not newer, refuses while a backup or restore runs, replaces its binary (the old one is kept as `.prev`)
   and restarts. The **Version** column shows the new version afterwards.

Only administrators can start agent updates.

> **Status:** The appliance takes the agent release from `/usr/share/nexus/agent` in its image. The current image
> **does not ship an agent bundle there yet**; the release process must add it. Agent self-update was tested in the
> Linux lab VMs; on Windows, MSI installs refuse it and are updated with a newer MSI (major upgrade, tested on
> Windows Server 2022).

## Plugin upgrades

Plugins are updated by uploading a newer signed bundle on the **Plugins** page. The upgrade waits for approval (when
approvals are enabled), and older installed versions stay available, so you can switch back with **Make current**.
See [12 Plugins](12-plugins.md).

## Proxmox VE node plugin

The NexusBackup storage plugin on your Proxmox VE nodes is a Debian package (`nexusbackup-pve_<version>_all.deb`,
built by `pve-plugin/build-deb.sh`). The appliance does not update it. Install a new version on **every** node of the
cluster the same way as the first one (see [04 Sources](04-sources.md)), for example
`apt install ./nexusbackup-pve_<version>_all.deb`.
