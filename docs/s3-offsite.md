# S3 offsite target (plan §9.3)

An S3-compatible bucket can replace the Hetzner Storage Box as a tenant's
offsite target. The pack format, the layout on the remote and the offsite
engine (`offsite::target::Target`: upload, retention, GC, verify, inventory,
restore, DR) stay the same. What changes is the immutability layer: instead of
Storage Box snapshots in the Hetzner console, every object is protected by
**S3 Object Lock in compliance mode**.

## How the appliance uses the bucket

```
<prefix>/packs/<pp>/<id>.pack                        cold storage class (storage_class_packs)
<prefix>/snapshots/<source>/<time>/{<name>.idx,manifest}   hot (storage_class_meta)
<prefix>/keys/…                                      wrapped key escrow, hot
```

Client (`crates/offsite/src/s3.rs`, own SigV4 implementation, no AWS SDK):

- AWS Signature V4 in the `Authorization` header. The payload SHA-256 is
  always computed and signed (`x-amz-content-sha256`, never
  `UNSIGNED-PAYLOAD`). Bodies also carry `Content-MD5` (Object Lock requires
  it for writes).
- HTTPS only (rustls, ring). Trust: the public web PKI (compiled-in Mozilla
  roots), or exactly the certificates in `ca_pem`: a private CA, or the
  endpoint's own certificate as a pin. Redirects and proxies are ignored.
- Path-style (`https://endpoint/bucket/key`) or virtual-hosted style
  (`https://bucket.endpoint/key`). Bucket names with dots and IP endpoints
  need path style.
- **Never overwrites.** Before each upload, a HEAD checks whether the object
  exists; if it does, the upload fails with `AlreadyExists`. The PUT itself
  carries `If-None-Match: *` (AWS since 2024, MinIO, Ceph RGW), so a writer
  that loses a race gets 412. On providers that ignore `If-None-Match`, two
  writers of the same new key can still race between HEAD and PUT. The
  appliance is the only writer of its prefix and pack ids are random, so
  this needs a second appliance on the same prefix. With versioning, the
  older version still exists.
- Objects larger than 64 MiB use multipart uploads with 16 MiB parts. Each
  part carries its MD5 and signed SHA-256, `If-None-Match: *` goes on the
  complete request, and the upload is aborted on failure. Packs are 32–36 MiB,
  so normally single PUTs.
- Retries cover transport errors, 5xx, 429 and the throttling codes
  (`SlowDown`, `RequestTimeout`, `InternalError`, `ServiceUnavailable`). The
  backoff starts at 500 ms and doubles up to 30 s, with jitter, for 4 retries.
  Other 4xx answers are final and mapped to clean errors: 404 → NotFound,
  403/locked → PermissionDenied, 412 → AlreadyExists,
  `RequestTimeTooSkewed` → hint to fix the clock.
- Answers are bounded: XML at most 16 MiB, a whole-object GET at most 1 GiB, a
  ranged GET exactly the requested length. The XML reader is tiny, refuses
  DTDs, limits nesting depth, and has the fuzz target `s3_xml`.

## Lock semantics

With `lock: true` (the bucket must have Object Lock enabled):

| Object | Retain-until (compliance mode) |
|---|---|
| snapshot files (`manifest`, `*.idx`) | the snapshot's offsite lock |
| pack | the maximum offsite lock over all snapshots that reference a chunk in it |
| key escrow (`keys/…`) | the longest offsite lock of all snapshots (DR needs the keys) |

- **Upload.** New packs and snapshot files are written with lock headers. Older
  packs that the new snapshot shares (dedup) get their lock extended first
  (`PutObjectRetention`). Only then is the manifest written, so a snapshot
  never counts as offsite while some of its data is unlocked.
- **Retention.** Offsite retention computes locks independently: GFS
  promotion, e.g. a daily snapshot that becomes a monthly one. When a
  snapshot's lock grows, the remote locks of its packs and files are extended
  first. Only after that is the local lock written. Locks only grow, and
  compliance mode refuses shortening anyway. `extend_lock` treats "already
  locked longer" as success.
- **GC.** Packs whose lock still runs are skipped (`GcStats.packs_locked`) and
  retried on a later run. That covers both the lock recorded locally
  (`state/packs/<id>.lock`) and the lock implied by live snapshots. Deleting
  them would only add a delete marker and free nothing, and repacking would
  duplicate the data.
- **Deleting** an unlocked snapshot or pack is a plain `DeleteObject`. On a
  versioned bucket (Object Lock implies versioning) that adds a delete marker.
  The data version stays until a lifecycle rule removes it (below). MinIO
  may keep listing a "directory" whose objects all carry delete markers, as an
  empty common prefix, until the markers expire. The engine only trusts
  snapshot directories that contain a manifest.
- **DR** (`nexus-offsite … dr`): the local inventory is rebuilt from the bucket
  alone. Snapshot locks are read back from the manifest objects (HEAD), so the
  extensions made by retention survive DR. Pack locks are read back the same
  way.
- **Verify / inventory / restore** work as with SFTP. The inventory check
  reports packs or manifests that disappeared (also those hidden by a delete
  marker).
- **Snapshots with an already expired lock** (`lock_until <= now`, e.g. the
  minimum lock of 0 in tests) are stored without lock headers.

The appliance records lock dates in Unix seconds and S3 compares them with the
provider's clock. The appliance's compliance clock and NTS keep the two close.
A lock that has passed on the appliance side but not yet at the provider only
delays the actual deletion.

## Configuration

`tenants.offsite` (catalog JSON, via the web UI "Tenants" → "S3 object storage",
or `PUT /api/v1/tenants/{name}`):

```json
{
  "remote": {
    "type": "s3",
    "endpoint": "https://fsn1.your-objectstorage.com",
    "region": "fsn1",
    "bucket": "nexus-acme",
    "prefix": "appliance1",
    "access_key": "…",
    "secret_key": "…",
    "path_style": false,
    "ca_pem": null,
    "storage_class_packs": null,
    "storage_class_meta": null,
    "lock": true
  },
  "uploaders": 4,
  "bwlimit": null
}
```

| Field | Notes |
|---|---|
| `endpoint` | `https://host[:port]`, no path. HTTP is refused. |
| `region` | The signing region (`us-east-1` for MinIO unless configured otherwise). |
| `bucket`, `prefix` | All objects live under `prefix/`, so one bucket can hold several appliances or tenants. One bucket per tenant is still recommended (separate credentials, separate lock and lifecycle policies). |
| `access_key`, `secret_key` | `secret_key` is write-only: the web-api seals it to the scheduler (`sealed:v1:`). It is never returned (`secret_key_set: true` instead), redacted in quorum lists and the audit log, and bound to `endpoint`, `region`, `bucket`, `access_key`, `path_style` and `ca_pem`. Changing any of those requires re-entering the key. |
| `ca_pem` | Optional PEM: a private CA, or the endpoint certificate itself (pin). |
| `storage_class_packs` / `storage_class_meta` | Optional `x-amz-storage-class` per object kind. Only classes that are readable without a restore request are useful, because DR reads pack footers and verify downloads packs: e.g. `STANDARD_IA` or `GLACIER_IR` for packs, `STANDARD` for indexes. `GLACIER` and `DEEP_ARCHIVE` are refused. Mind minimum storage durations: GC and repacking delete packs, and early deletion is billed. |
| `lock` | Set only for buckets created with Object Lock. |
| `conditional_put` | (job config only, default `true`) Set to `false` for providers that reject `If-None-Match` on PUT. |

The scheduler opens the sealed key only in memory and writes it into the 0600
job dir (`offsite-s3.secret`, `offsite-ca.pem`). `nexus-offsite` reads
`secret_key_file` / `ca_file`. Changing or removing an existing offsite target
needs a quorum, as for SFTP.

**Firewall.** The scheduler adds the endpoint host:port to the outbound
allow-list. With virtual-hosted style it adds `<bucket>.<host>`. The name is
resolved when the list is synced (every tick). Providers whose DNS rotates
through many addresses (AWS S3) can hand `nexus-offsite` an address that is
not in the set yet. Prefer providers with stable addresses (Hetzner, Wasabi,
on-prem), or retry. Allowing provider IP ranges is an open item.

**SELinux.** `nexus_offsite_t` may connect to `http_port_t` (443) and to
unreserved ports (MinIO's 9000 and the like). No access to the system
certificate store is needed.

## Bucket setup

Always:

1. A **separate account or project** for the backups. It is not the account
   that runs anything else, and its root credentials are not on the appliance.
2. A **new bucket with Object Lock enabled** (this also turns on versioning;
   most providers allow enabling Object Lock only at creation). Do **not**
   configure a default retention: the appliance sets the right date per
   object, and a default retention would also lock objects the appliance wants
   to delete, such as dead packs.
3. A **lifecycle rule** that removes noncurrent versions some days after they
   became noncurrent, plus expired delete markers and incomplete multipart
   uploads. Lifecycle never deletes a version whose lock still runs; it
   catches up after the lock ends. The days after the lock act as an extra
   detection window, like the Storage Box snapshots.
4. A **user or key restricted by the policy below**: no `DeleteObjectVersion`,
   no `BypassGovernanceRetention`, no bucket configuration changes.

### Restricted policy (AWS IAM / MinIO)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ApplianceBucket", "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketObjectLockConfiguration", "s3:ListBucketMultipartUploads"],
      "Resource": ["arn:aws:s3:::BUCKET"] },
    { "Sid": "ApplianceObjects", "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:PutObjectRetention", "s3:GetObjectRetention",
                 "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
      "Resource": ["arn:aws:s3:::BUCKET/*"] },
    { "Sid": "NeverDestroyHistory", "Effect": "Deny",
      "Action": ["s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectLegalHold",
                 "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketVersioning",
                 "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration",
                 "s3:PutReplicationConfiguration", "s3:DeleteBucket"],
      "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"] }
  ]
}
```

(`crates/offsite/testbox-s3/policy.json` is the same policy for bucket
`nexus`, tested against MinIO.)

**What the appliance can do with these credentials:** list, read, write new
objects, set and extend locks, and delete the *current* version of an object.
On a versioned bucket, a delete only adds a delete marker.

**What it cannot do:** delete or overwrite a locked version (Object Lock
refuses even the root account in compliance mode), shorten a lock, delete any
noncurrent version, change versioning, lifecycle, lock configuration or the
bucket policy, or delete the bucket. Deleted data stays recoverable from its
noncurrent version until the lock ends plus the lifecycle delay.

### MinIO (on-prem, and the test box)

```sh
mc mb --with-lock site/nexus-acme
mc ilm rule add --noncurrent-expire-days 7 --expire-delete-marker site/nexus-acme
mc admin policy create site nexus-appliance policy.json
mc admin user add site appliance-acme '<secret>'
mc admin policy attach site nexus-appliance --user appliance-acme
```

Use `path_style: true`. For a self-signed endpoint certificate, put it into
`ca_pem` (pin). Upstream MinIO stopped publishing binaries and images in 2025.
`crates/offsite/testbox-s3/run.sh` uses the community build
`docker.io/pgsty/minio` (includes `mc`).

### AWS S3

1. Create the bucket in a dedicated AWS account with **Object Lock enabled**
   and no default retention.
2. Lifecycle configuration (`aws s3api put-bucket-lifecycle-configuration`,
   run with an admin identity, not the appliance's):

```json
{ "Rules": [ { "ID": "nexus-cleanup", "Status": "Enabled", "Filter": {},
    "NoncurrentVersionExpiration": { "NoncurrentDays": 7 },
    "Expiration": { "ExpiredObjectDeleteMarker": true },
    "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 1 } } ] }
```

3. Create an IAM user with the policy above and an access key.
4. Configure `endpoint` = `https://s3.<region>.amazonaws.com`, `region` =
   `<region>`, `path_style: false`. Storage classes: e.g.
   `storage_class_packs: "STANDARD_IA"` (30-day minimum) or `"GLACIER_IR"`
   (90-day minimum; GC repacking within that period is billed as early
   deletion), and `storage_class_meta: "STANDARD"`.

### Hetzner Object Storage

- Endpoint `https://<location>.your-objectstorage.com` (`fsn1`, `nbg1`,
  `hel1`), region = the location.
- Create the bucket with Object Lock enabled in the Cloud Console (or with any
  S3 client: `aws s3api create-bucket --object-lock-enabled-for-bucket`).
  Apply the lifecycle rule with an admin key.
- Hetzner's S3 credentials are project-wide and cannot be restricted by an IAM
  policy. Use a separate Hetzner project for the backup buckets, and rely on
  compliance mode for immutability: the appliance's key can still delete
  current versions and unlocked noncurrent versions. Check the current Hetzner
  documentation for bucket policy support before relying on the restricted
  policy.
- Storage classes are not supported: leave both empty.

### Wasabi

- Endpoint `https://s3.<region>.wasabisys.com`, region e.g. `eu-central-2`.
- Create the bucket with Object Lock (Wasabi enables versioning with it). Use a
  sub-user with the policy above. Wasabi supports IAM-style policies.
- Wasabi bills a minimum storage duration (90 days by default): deleted and
  repacked packs keep costing until then.
- Storage classes: leave empty.

## Threat model delta (docs/threat-model.md T5)

| | Storage Box (SFTP) | S3 with Object Lock (compliance) |
|---|---|---|
| Compromised appliance deletes the offsite copy | Possible. Recoverable from box snapshots for ~6 weeks (detection window). | Not possible for locked data: delete only adds markers, and the versions stay until their lock ends plus the lifecycle delay. Unlocked data (lock expired) follows the lifecycle delay. |
| Compromised appliance overwrites objects | The append-only client refuses, but an attacker with the key can write anything. Snapshots keep the old state. | New versions only. The locked version stays and stays readable. |
| Compromised appliance shortens retention | Box snapshots unaffected. | Compliance mode refuses shortening. With the restricted policy it also cannot change versioning, lifecycle or the bucket policy. |
| Attacker extends locks to absurd dates (cost) | n/a | Possible (`PutObjectRetention`). Bounded by the provider bill, detected by monitoring the bucket size. |
| Provider admin / root account | Can delete the box. | Cannot delete locked versions in compliance mode (except by closing the account). |
| Stolen appliance credentials, read side | Read all (encrypted) data. | Same. Data is AEAD-encrypted per tenant, names are random. |

**Residual risks:**

- New backups after a compromise can be withheld or written unlocked. The
  offsite-lag and inventory alerts detect this.
- A provider without real compliance-mode semantics gives no guarantee: test
  with a delete of a locked version, as `tests/s3.rs` does against MinIO.
- Hetzner keys are project-wide (above).

## Tests

```sh
crates/offsite/testbox-s3/run.sh start
eval "$(crates/offsite/testbox-s3/run.sh env)"
cargo test -p offsite --test s3 -- --nocapture
crates/offsite/testbox-s3/run.sh stop      # removes all data, locked or not
```

Without the environment the tests print `SKIP` and pass. The SigV4 known-answer
tests (AWS documentation examples) and the lock logic tests against a strict
lock double (`tests/target.rs`) run everywhere.

Against MinIO with TLS and the restricted user:

- `conformance()`, ListObjectsV2 pagination (1100 keys), and the concurrent
  conditional-put race (exactly one winner).
- Object Lock: lock read-back, overwrite refused, version delete refused for
  the appliance user (policy) and for root (WORM), lock shortening ignored,
  extension, delete marker.
- Multipart upload of 100 MiB, auth and TLS errors.
- The engine flow: upload, lock extension by retention, GC deleting the
  unlocked dead pack and skipping three locked ones, verify, DR rebuild with
  locks restored, restore bit-exact, and the inventory alert after a pack was
  deleted (while its locked version survives).
