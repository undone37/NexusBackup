# 09 Users and access

Every person who works with the appliance gets an own account with a role. There are two kinds of accounts:

- **Local accounts** (appliance accounts) have a password and a TOTP authenticator. They are created by an
  administrator, but **the administrator never sets or learns another person's password or authenticator**: the new
  user activates the account with a one-time activation code and chooses both themselves.
- **Single sign-on accounts** sign in through your organization's identity provider (Microsoft Entra ID, Keycloak,
  Okta, Authentik, …). They are created automatically at the first sign-in; see
  [Single sign-on (OIDC)](#single-sign-on-oidc).

## Roles

| Role | May | May not |
|---|---|---|
| **Administrator** | configure tenants, sources, agents, policies, groups, users, replication, plugins and **Settings** (approvals, alert delivery, single sign-on, appliance SSH keys, updates); run backups and restores; enable approvals; confirm a large GC while approvals are disabled; read the audit log | approve own requests |
| **Security officer** | approve or reject requests of others; read everything incl. the audit log and verify the chain; read replication, plugins and all **Settings** tabs | change configuration, run backups or restores |
| **Operator** | run backups (**Back up now**), restores and file downloads; cancel queued jobs; acknowledge alerts; start a replication sync; read approvals, replication, plugins and the **Settings** tabs Approvals, Appliance SSH keys and Updates | change configuration, approve requests, read the audit log |
| **Tenant user** | see one tenant's dashboard, snapshots and jobs; restore and download that tenant's data | everything else |

Any account can be limited to one tenant with the **Tenant** field (required for tenant users). Tenant-scoped
accounts see only their tenant's data and do not see alerts, approvals, replication or settings.

The appliance needs at least one enabled administrator; the last one cannot be disabled or demoted. For approvals to
work you need at least two people who can approve (administrators or security officers), see
[10 Approvals and audit](10-approvals-and-audit.md).

## The Users page

Open **Configuration → Users**.

![Users](images/users.png)

The **State** column shows **Active**, **Disabled** or **Pending activation** with the date until which the code is
valid ("waiting for the second code part" or "code expired" are also possible). Accounts that sign in through the
identity provider carry an extra **Single sign-on** chip and offer only **Edit** (see
[Single sign-on accounts on the Users page](#single-sign-on-accounts-on-the-users-page)).

## Creating an account

This creates a local account. Single sign-on accounts are not created here; they appear at their first sign-in.

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

Click **Edit** next to a local account to change its **Role**, **Tenant** or the **Disabled** flag.

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

If you are the **only** administrator and lost your authenticator or password, nobody can issue you a new code in
the web interface. Use the console break-glass procedure with the recovery key: see
[14 Disaster recovery](14-disaster-recovery.md#break-glass-the-only-administrator-lost-their-authenticator).

> **Status:** There is no procedure yet for the case that approvals can no longer be granted because approvers are
> unavailable. Always keep at least two people who can sign in as administrator or security officer.

## Sessions and sign-in protection

- Sessions end after 30 minutes without activity and after 12 hours at the latest.
- 5 failed sign-ins (or activation attempts) for a user or from an address within 15 minutes lock further attempts for
  15 minutes.
- Each authenticator code can be used once; a replayed code is refused.
- Passwords are stored as Argon2id hashes; authenticator secrets are stored encrypted.
- Single sign-on accounts get the same sessions as local accounts; their password and second factor are checked by
  the identity provider.

> **Status:** Local accounts support only TOTP authenticators. WebAuthn (security keys) is planned; with single
> sign-on, the identity provider can require security keys.

## Single sign-on (OIDC)

With single sign-on, people sign in with the account of your organization's identity provider (IdP) through OpenID
Connect: **Sign in with …** on the sign-in page sends them to the IdP and back. Any standard OIDC provider works, for
example Microsoft Entra ID, Keycloak, Okta or Authentik.

How it works:

- **Accounts are created at the first sign-in** ("just in time"). Nobody has to create them on the appliance.
- **Role and tenant come from group mappings.** You map IdP groups to appliance roles (and, for tenant users, one
  tenant). At every sign-in the appliance reads the user's groups from the IdP's answer and sets the account's role
  and tenant again, so a change at the IdP takes effect at the next sign-in.
- **No matching mapping = no access.** If none of the user's groups is mapped, the sign-in is refused, an existing
  account is disabled, and the refusal is audited (`auth.oidc_denied`).
- **An administrator's "Disabled" wins.** An SSO account an administrator disabled stays disabled: the next SSO
  sign-in is refused and does not enable it again; only an administrator can.
- **SSO accounts never take over local accounts.** Accounts are matched by the IdP's subject, not by name. If a local
  account already has the same user name, the SSO sign-in is refused (audited as `auth.oidc_denied`).
- **The highest privilege wins.** If several mappings match, the user gets the role of the highest-privileged one:
  Administrator, then Security officer, then Operator, then Tenant user.
- **Multi-factor authentication is the IdP's job.** Single sign-on accounts have no password and no authenticator on
  the appliance and cannot use the appliance sign-in form. Enforce MFA at the IdP (see the examples below).
- **Local accounts keep working** as break-glass access, for example when the IdP is down. Keep at least one local
  administrator with a stored password and authenticator.
- Approvals treat single sign-on users like local users (by name): nobody can approve their own request.

Audit entries: `auth.oidc_login` (sign-in), `user.oidc_created` (first sign-in), `auth.oidc_denied` (refused),
`settings.oidc` (settings changed).

> **Status:** Single sign-on was tested against the demo backend only. The appliance-side implementation and a lab
> run against Keycloak are in progress; a run against Microsoft Entra ID is pending.

### Before you start

- The IdP must be reachable over HTTPS from the appliance (it reads the IdP's configuration and signing keys and
  exchanges the sign-in code there) and from the users' browsers. The appliance adds the IdP's host to its outbound
  firewall allow-list.
- Open **Settings → Single sign-on** through the same address your users will use (e.g.
  `https://backup.example.com:8443/`). The **Redirect URI to register at the identity provider** is built from it.
- Create the groups at the IdP first, for example `nexus-admins`, `nexus-security`, `nexus-operators` and one group
  per tenant for tenant users (`acme-backup-users`).

### Example: Keycloak

1. In your realm (e.g. `nexus`), open **Clients → Create client**: client type **OpenID Connect**, **Client ID**
   `nexusbackup`. Turn on **Client authentication** and keep only **Standard flow** as authentication flow.
2. Under **Valid redirect URIs**, enter the **Redirect URI** shown in **Settings → Single sign-on**, e.g.
   `https://backup.example.com:8443/api/v1/auth/oidc/callback`. Save.
3. Copy the **Client secret** from the client's **Credentials** tab.
4. Create the groups claim: **Client scopes → Create client scope** named `groups` (type OpenID Connect), then in its
   **Mappers** add **By configuration → Group Membership** with **Token Claim Name** `groups`, **Full group path**
   off and **Add to ID token** on. Add the scope to the `nexusbackup` client (**Client scopes → Add client scope**,
   as Default).
5. Enforce a second factor in the realm, for example with **Configure OTP** as a default required action, or with a
   browser flow that requires OTP or WebAuthn.
6. The **Issuer URL** is `https://<keycloak host>/realms/<realm>`, e.g. `https://idp.example.com/realms/nexus`.

The appliance's defaults fit Keycloak: scopes `openid profile email` (the `groups` client scope added as **Default**
in step 4 is included without being requested), user name claim `preferred_username`, groups claim `groups`.

### Example: Microsoft Entra ID

1. In the Microsoft Entra admin center, open **App registrations → New registration**: name `NexusBackup`,
   supported account types **Accounts in this organizational directory only**, redirect URI platform **Web** with the
   **Redirect URI** shown in **Settings → Single sign-on**. Register.
2. Note the **Application (client) ID** and the **Directory (tenant) ID**. The **Issuer URL** is
   `https://login.microsoftonline.com/<directory (tenant) ID>/v2.0`.
3. **Certificates & secrets → New client secret**: copy the secret's **Value** (not its ID). Entra client secrets
   expire (at most after 24 months): note the date and enter a new secret in **Settings → Single sign-on** before
   then.
4. **Token configuration → Add groups claim**: choose **Security groups** (or **Groups assigned to the application**,
   recommended when users are in many groups) and, for the ID token, **Group ID**. The `groups` claim then contains
   the groups' **object IDs** (e.g. `3f2b6c1e-…`); use these object IDs as **IdP group** in the mappings. Users in
   more than 200 groups get no groups claim unless you limit it to groups assigned to the application.
5. In **Settings → Single sign-on**, keep the default **Scopes** `openid profile email` (Entra ID has no `groups`
   scope; the claim comes from the token configuration), **User name claim** `preferred_username` (the user's
   sign-in name, e.g. `anna@example.com`; SSO user names may contain `@`) and **Groups claim** `groups`.
6. Require MFA with a Conditional Access policy for the NexusBackup application. Optionally set **Assignment
   required** on the enterprise application, so that only assigned users and groups can sign in at all.

### Configure single sign-on on the appliance

Open **Configuration → Settings → Single sign-on** (administrators; security officers see it read-only).

![Settings: Single sign-on with four group mappings](images/settings-sso.png)

1. Under **Identity provider**, tick **Allow single sign-on** and fill in:

   | Field | Content |
   |---|---|
   | **Issuer URL** | the IdP's issuer (`https://…`). The appliance reads `/.well-known/openid-configuration` below it. |
   | **Client ID**, **Client secret** | from the IdP registration. The secret is write-only ("Stored — leave empty to keep the current value."). |
   | **Redirect URI to register at the identity provider** | read-only; **Copy** it into the IdP registration |
   | **Scopes** | space separated, must include `openid`; default `openid profile email` |
   | **User name claim** | the claim that becomes the appliance user name; default `preferred_username` |
   | **Groups claim** | the claim with the user's groups; default `groups` |
   | **Button text on the sign-in page** | e.g. `Sign in with Keycloak` (required, at most 64 characters) |

2. Under **Group mappings**, click **Add mapping** for each group: **IdP group** (the group name or ID exactly as the
   IdP sends it), **Role**, and, for the role **Tenant user** only, the one **Tenant** the user may see (an appliance
   account belongs to one tenant or to all; the other roles always see all tenants). The
   bin icon removes a mapping. While the list is empty, the page warns "No mappings yet: nobody can sign in with
   single sign-on."
3. Click **Save**. With approvals enabled, saving creates an approval request (`oidc.update`) because it changes who
   can sign in; another administrator or security officer must approve it on **Approvals**.
4. Click **Test connection**. It checks the saved issuer's discovery document and signing keys (JWKS) and shows one
   green or red line per check. It always uses the saved settings, so test after saving (and after the approval).
5. Open the sign-in page in a private browser window, click **Sign in with …** and sign in at the IdP. You land on the
   Dashboard; the new account appears on **Users** with the **Single sign-on** chip.

To turn single sign-on off, clear **Allow single sign-on** and save. The button disappears from the sign-in page;
local accounts are not affected.

### Single sign-on accounts on the Users page

![Editing a single sign-on account](images/user-sso.png)

- **Role** and **Tenant** are greyed out: they come from the group mappings and are refreshed at every sign-in.
  Change the group membership at the IdP, or the mapping, instead.
- There is no **Issue new activation code** and no **Reset authenticator**: password and second factor are managed by
  the IdP. A lost phone or password is handled there.
- **Disabled** blocks the account on the appliance.
- To take access away, remove the person from the mapped groups at the IdP (the next sign-in is refused) and tick
  **Disabled** here.

If sign-in through the IdP fails, the sign-in page shows the reason; see
[15 Troubleshooting](15-troubleshooting-faq.md#single-sign-on).
