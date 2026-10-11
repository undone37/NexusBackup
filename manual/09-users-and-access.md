# 09 Users and access

Every person who works with the appliance gets an own account with a role, a password and a TOTP authenticator.
Accounts are created by an administrator, but **the administrator never sets or learns another person's password or
authenticator**: the new user activates the account with a one-time activation code and chooses both themselves.

## Roles

| Role | May | May not |
|---|---|---|
| **Administrator** | configure tenants, sources, agents, policies, groups, users, replication and plugins; run backups and restores; enable approvals; confirm a large GC while approvals are disabled; read the audit log | approve own requests |
| **Security officer** | approve or reject requests of others; read everything incl. the audit log and verify the chain; read replication and plugins | change configuration, run backups or restores |
| **Operator** | run backups (**Back up now**), restores and file downloads; cancel queued jobs; acknowledge alerts; start a replication sync; read approvals, replication and plugins | change configuration, approve requests, read the audit log |
| **Tenant user** | see one tenant's dashboard, snapshots and jobs; restore and download that tenant's data | everything else |

Any account can be limited to one tenant with the **Tenant** field (required for tenant users). Tenant-scoped
accounts see only their tenant's data and do not see alerts, approvals or replication.

The appliance needs at least one enabled administrator; the last one cannot be disabled or demoted. For approvals to
work you need at least two people who can approve (administrators or security officers), see
[10 Approvals and audit](10-approvals-and-audit.md).

## The Users page

Open **Configuration → Users**.

![Users](images/users.png)

The **State** column shows **Active**, **Disabled** or **Pending activation** with the date until which the code is
valid ("waiting for the second code part" or "code expired" are also possible).

## Creating an account

1. Click **New user**.
2. Enter the **Name** (letters, digits, `.`, `_`, `-`), choose the **Role** and, for tenant users, the **Tenant**.
   There is no password field.

   ![New user dialog](images/user-new.png)

3. Click **Create**. A dialog shows the **Activation code** and the **Activation link** exactly once.

   ![Activation code for a new operator](images/user-activation-code.png)

4. Give the user the code and the link, preferably through two different channels (for example the link by email
   and the code by phone). The code is valid for **72 hours** and works only once. The appliance stores only a hash
   of it; if it is lost, issue a new one.

### Administrators and security officers (split code)

With approvals enabled, creating an **Administrator** or **Security officer** is an approval request, and the code
is split in two halves so that no single person can create an account they control:

1. You (the requesting administrator) receive only **part 1 of 2** and a "Pending approval" message. Give this half to
   the new user.

   ![The first half of a split activation code](images/user-activation-part1.png)

2. Another administrator or security officer approves the request on the **Approvals** page and then receives
   **part 2 of 2**. They give it to the user through a different channel.

   ![The approver receives the second half](images/approvals-second-half.png)

3. The user enters both halves one after the other in the **Activation code** field. The code is valid for 72 hours
   from the approval.

With approvals disabled (single administrator), the whole code is shown at once.

## Activating your account

You received a user name, an activation link and an activation code (or two halves of it).

1. Open the activation link, or open the sign-in page and click **Activate account**.
2. Enter your **User name** and the **Activation code** (case, spaces and dashes do not matter; with two parts, first
   the part from the administrator who created the account, then the part from the approver). Click **Continue**.

   ![Step 1: activation code](images/activate-code.png)

3. Choose your **New password** (at least 12 characters), repeat it and click **Continue**.

   ![Step 2: password](images/activate-password.png)

4. Scan the QR code with an authenticator app (any TOTP app, e.g. on your phone) or type the **Secret** into the app.
   Enter the 6-digit code the app shows and click **Activate**.

   ![Step 3: authenticator](images/activate-authenticator.png)

5. Sign in with your user name, your new password and a code from the app.

   ![Activation done](images/activate-done.png)

The QR code and secret are shown only to you, only once. If the activation fails five times, it is locked for 15
minutes like a sign-in.

## Changing an account

Click **Edit** next to an account to change its **Role**, **Tenant** or the **Disabled** flag.

- Granting **Administrator** or **Security officer** needs approval when approvals are enabled. A pending account must
  be activated by its owner before it can get a privileged role.
- With approvals enabled, a change that would leave fewer than two people able to approve is refused.
- Disabled accounts cannot sign in; their sessions end. Re-enabling an administrator or security officer needs
  approval when approvals are enabled.

### Your own password and authenticator

- To change your own password, **Edit** your own account, enter the **New password for your own account**, then
  confirm with **Your current password** and **Your authenticator code**.
- **Reset authenticator** (shown on your own row) issues a new TOTP secret for your account, after the same
  re-authentication. Scan the new QR code; the old one stops working immediately.

Wrong re-authentication attempts count toward the sign-in lockout and are audited.

### Lost password or authenticator

Another administrator clicks **Issue new activation code** on your row and confirms with their own password and
authenticator code. Your old password and authenticator stop working at once, your sessions end, and you activate
the account again with the new code as described above.

For an administrator or security officer with approvals enabled, the new code is split like at creation and needs
approval; the old credentials keep working until the request is approved.

> **Status:** There is no recovery path for the *only* administrator who lost the authenticator, and no console
> procedure yet for the case that approvals can no longer be granted because approvers are unavailable. Always keep
> at least two people who can sign in as administrator or security officer.

## Sessions and sign-in protection

- Sessions end after 30 minutes without activity and after 12 hours at the latest.
- 5 failed sign-ins (or activation attempts) for a user or from an address within 15 minutes lock further attempts for
  15 minutes.
- Each authenticator code can be used once; a replayed code is refused.
- Passwords are stored as Argon2id hashes; authenticator secrets are stored encrypted.

> **Status:** Only TOTP authenticators are supported. WebAuthn (security keys) and single sign-on (OIDC) are planned.
