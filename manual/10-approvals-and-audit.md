# 10 Approvals and audit

This chapter is mainly for **security officers** and administrators. It covers the four-eyes approval system and the
tamper-evident audit log.

## What needs approval

While approvals are **enabled**, these actions do not take effect when someone clicks them. They become requests that
a different administrator or security officer must approve:

| Area | Action (as shown on the Approvals page) |
|---|---|
| Configuration | deleting a tenant, source, policy, protection group or agent (`tenant delete`, `source delete`, …) |
| Retention | lowering any GFS value or switching off **Copy offsite** (`policy update`); moving a group to a weaker policy (`group update`) |
| Accounts | granting **Administrator** or **Security officer**, re-enabling such an account, a new activation code for one (`user update`) |
| Storage | deleting a snapshot by hand (`snapshot delete`; only unlocked snapshots can be requested); a garbage collection that would delete more than 20 % of a tenant's chunks (`gc_large`, requested by `scheduler`) |
| Replication | creating a peer, exporting tenant keys to it, revoking a peer, deleting an enrolled replication source, lowering a replication source's retention |
| Plugins | installing or upgrading a plugin, switching to another installed version, disabling or removing a plugin, adding or removing a publisher key |
| Single sign-on | saving the single sign-on settings (identity provider, client secret, group mappings), because it changes who can sign in (`oidc update`) |
| Appliance SSH keys | rotating an appliance SSH key (`ssh key rotate`) |
| Updates | **Install now**: installing an available appliance update without waiting for the maintenance window (`update apply`) |
| Approvals | disabling the approval requirement itself (`approvals disable`) |

Rules:

- The requester can never decide their own request. Any **other** enabled administrator or security officer can.
- A request expires after **72 hours** without a decision.
- Approving runs the action immediately and cannot be undone. Some actions (the replication key export, a large GC, a snapshot delete)
  are carried out by the scheduler shortly after the approval; their state goes from **Approved** to **Executed**.
- Requests never show secrets: passwords, keys and activation codes are not part of a request.

## Deciding requests

Open **Approvals** in the sidebar, or click the stamp icon in the top bar; both show the number of pending requests.
By default only pending requests are listed; clear **Pending only** to see the history. The chip next to it shows
whether approvals are **Enabled** or **Disabled**; **Approval settings** opens **Settings → Approvals**.

![Approvals as seen by a security officer](images/approvals.png)

Each request shows the action, who requested it and when, when it expires, and its parameters. For changes to policies
and groups you see a **Change** table: **Before** and **After** for every field, with changed rows highlighted.

![The change table of a weakened policy](images/approvals-diff.png)

Before you approve:

- Check that the requester is who you expect and that the change was agreed, preferably by talking to them.
- For a replication key export, compare the **keyd_fingerprint** with the key service fingerprint shown on the
  secondary appliance's Replication page (see [08 Replication](08-replication.md)).
- For a plugin, compare the bundle SHA-256 and the signer with what the publisher announced
  (see [12 Plugins](12-plugins.md)).

Click **Approve** (and confirm) or **Reject**. When you approve the creation of an administrator or security officer,
you receive the second half of the user's activation code; pass it to the user through a different channel than the
first half (see [09 Users and access](09-users-and-access.md#administrators-and-security-officers-split-code)).

Your own requests show "You requested this — another administrator or security officer must decide."
Administrators see the same page and can decide requests of others:

![Approvals as seen by the administrator who made the requests](images/approvals-admin.png)

Operators can read the page but not decide.

## Enabling and disabling approvals

The approval requirement is switched under **Configuration → Settings → Approvals** (or **Approval settings** on the
Approvals page). The **Approval requirement** box shows the current setting (**Enabled** or **Disabled**), what it
means, and how many people can approve (enabled, activated administrators and security officers). Only
administrators see the button; security officers and operators see the box read-only.

![Settings: Approvals, with approvals enabled](images/settings-approvals.png)

- **Enable approvals** (administrators): takes effect immediately. It is refused unless at least one other person
  could approve; otherwise nothing could ever be approved again.
- **Disable approvals** (administrators): creates a request that another administrator or security officer must
  approve. Only one such request can be pending; while it is, the box says "Disabling is pending (request #N)." with
  a link to **Approvals**.
- After setup, approvals are enabled if the wizard created an administrator and a security officer, and disabled if
  there is a single administrator (see [02 Installation](02-installation.md)).

With approvals **disabled**:

- The actions in the table above take effect immediately. Each one is still audited, marked
  `"approvals": "disabled"`, and the message says "Approvals are disabled, so it took effect without a second person
  (audited)."
- Retention locks, write-only secrets and re-authentication still protect existing backups.
- A garbage collection over the 20 % limit still does not run on its own. It waits under
  **Large garbage collections waiting for confirmation** until an administrator clicks **Confirm and run GC**.
- Administrators see a recommendation banner on the Dashboard as soon as two people could approve.

![Approvals disabled, with a large GC waiting for confirmation](images/approvals-disabled.png)

## Audit log

Open **Audit log** (administrators and security officers).

![Audit log after verifying the chain](images/audit.png)

Every entry has a sequence number (**#**), **Time**, **Actor**, **Action**, **Target**, **Details** and **Hash**.
Entries are listed newest first; **Load more** pages back in time.

What is recorded:

- every change made through the web interface or API (create, update, delete, job requests), including the
  parameters, with secrets replaced by `<redacted>`;
- sign-ins, failed sign-ins (`auth.login_failed`), failed re-authentication (`auth.reauth_failed`), activations;
- single sign-on: sign-ins (`auth.oidc_login`), refusals (`auth.oidc_denied`), accounts created at first sign-in
  (`user.oidc_created`) and settings changes (`settings.oidc`);
- a break-glass recovery of an administrator on the console (`user.break_glass`, see
  [14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator));
- approval requests, decisions and executions (`quorum.request`, `quorum.approve`, `quorum.reject`, then the action
  itself with actor `system` or the scheduler);
- job state changes and scheduler events (e.g. `gc.confirm_required`, replication sessions on the primary,
  `replication_peer.enrolled`);
- the first-boot setup steps (`setup.*`).

### Verifying the chain

Each entry's hash covers the previous entry's hash and the entry's own fields. Click **Verify chain**: the appliance
recomputes every hash. "Chain intact (N entries)." means no entry was altered, removed or inserted in between.
"Chain BROKEN" names the first entry where the chain does not match; treat this as a security incident.

The audit table itself is append-only in the database (updates and deletes are refused by triggers).

> **Status:** The chain proves integrity only against changes that do not recompute it. A process with write access
> to the catalog database (or root) could rebuild the whole chain. The chain is not yet anchored outside the appliance:
> audit entries go to the local system journal without their details, and the image has no log-forwarding
> (syslog/SIEM) configuration yet. Keep this in mind when you rely on the audit log for compliance.

## Good practice

- Have at least two security officers, so approvals continue when one is absent.
- Review pending requests daily; they expire after 72 hours.
- Verify the audit chain regularly, for example weekly, and after any incident.
- Acknowledge alerts about approvals (`gc_quorum`) only after the request was decided.
