#!/usr/bin/env python3
"""Writes the seed corpora for the cargo-fuzz targets (crates/*/fuzz/seeds/<target>/).

Seeds are protocol-shaped inputs taken from the tests and the specs; the
offsite seeds come from a real upload (crates/offsite/fuzz/examples/mkseed.rs,
run by lab/fuzz/run.sh). Usage: lab/fuzz/mkseeds.py <repo root>
"""
import io, json, os, struct, sys, tarfile

root = sys.argv[1] if len(sys.argv) > 1 else "."


def put(crate, target, name, data):
    d = os.path.join(root, "crates", crate, "fuzz", "seeds", target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


# ---------------------------------------------------------------- nbd
NBDMAGIC, IHAVEOPT, REPLY_MAGIC = 0x4E42444D41474943, 0x49484156454F5054, 0x0003E889045565A9


def optrep(opt, ty, data=b""):
    return struct.pack(">QIII", REPLY_MAGIC, opt, ty, len(data)) + data


def server_hello():
    return struct.pack(">QQH", NBDMAGIC, IHAVEOPT, 3)


size = 3 << 20
go = optrep(7, 3, struct.pack(">HQH", 0, size, 3)) + optrep(7, 1)
sr = optrep(8, 1)
meta = optrep(10, 4, struct.pack(">I", 1) + b"qemu:dirty-bitmap:nexus") + optrep(10, 1)
meta2 = (optrep(10, 4, struct.pack(">I", 1) + b"qemu:dirty-bitmap:nexus")
         + optrep(10, 4, struct.pack(">I", 2) + b"base:allocation") + optrep(10, 1))


def sreply(flags, ty, cookie, payload):
    return struct.pack(">IHHQI", 0x668E33EF, flags, ty, cookie, len(payload)) + payload


bs = sreply(1, 5, 1, struct.pack(">I", 1) + struct.pack(">II", 1 << 20, 0) + struct.pack(">II", 2 << 20, 1))
read_simple = struct.pack(">IIQ", 0x67446698, 0, 1) + b"\xa5" * 65536
read_struct = (sreply(0, 1, 2, struct.pack(">Q", size // 3) + b"x" * 100)
               + sreply(1, 2, 2, struct.pack(">QI", size // 3 + 100, 65436)))
put("nbd", "nbd_client", "plain", b"\x00" + server_hello() + sr + go + read_simple + read_simple)
put("nbd", "nbd_client", "no_structured", b"\x00" + server_hello() + optrep(8, 0x80000001) + go + read_simple)
put("nbd", "nbd_client", "bitmap", b"\x01" + server_hello() + sr + meta + go + bs + read_struct)
put("nbd", "nbd_client", "bitmap2", b"\x02" + server_hello() + sr + meta2 + go
    + sreply(0, 5, 1, struct.pack(">III", 2, 3 << 20, 0)) + bs + read_struct)
put("nbd", "nbd_client", "error", b"\x01" + server_hello() + sr + meta + go
    + sreply(1, 0x8001, 1, struct.pack(">IH", 5, 4) + b"oops"))


def opt(o, data=b""):
    return struct.pack(">QII", IHAVEOPT, o, len(data)) + data


def req(ty, cookie, off, ln, flags=0):
    return struct.pack(">IHHQQI", 0x25609513, flags, ty, cookie, off, ln)


name = struct.pack(">I", 4) + b"disk"
put("nbd", "nbd_server", "go_read", struct.pack(">I", 3) + opt(8) + opt(7, name + b"\0\0")
    + req(0, 1, 0, 4096) + req(0, 2, (3 << 20) - 512, 512) + req(3, 3, 0, 0) + req(2, 4, 0, 0))
put("nbd", "nbd_server", "export_name", struct.pack(">I", 1) + opt(3) + opt(6, name + b"\0\0") + opt(1, b"disk")
    + req(1, 1, 0, 8) + b"12345678" + req(0, 2, 1 << 20, 1 << 16) + req(9, 3, 0, 0))
put("nbd", "nbd_server", "abort", struct.pack(">I", 3) + opt(99) + opt(2))

# ---------------------------------------------------------------- pve


def rec(tag, payload):
    return tag + struct.pack(">I", len(payload)) + payload


def tar_bytes(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, kind, data, link in members:
            ti = tarfile.TarInfo(name)
            ti.mtime = 1760000000
            ti.mode = 0o755 if kind == "dir" else 0o640
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
            elif kind == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, link
            elif kind == "hard":
                ti.type, ti.linkname = tarfile.LNKTYPE, link
            ti.size = len(data) if kind == "file" else 0
            t.addfile(ti, io.BytesIO(data) if kind == "file" else None)
    return b.getvalue()


normal = tar_bytes([("./", "dir", b"", None), ("./etc/", "dir", b"", None),
                    ("./etc/hostname", "file", b"ct200\n", None),
                    ("./etc/localtime", "sym", b"", "/usr/share/zoneinfo/UTC"),
                    ("./home/u/" + "x" * 120 + ".txt", "file", b"long name", None)])
hostile = tar_bytes([("../../etc/cron.d/evil", "file", b"* * * * * root id\n", None),
                     ("/abs/path", "file", b"abs", None),
                     ("lnk", "sym", b"", "/etc"), ("lnk/passwd", "file", b"pw", None),
                     ("hl", "hard", b"", "../../etc/shadow"), ("a/../../b", "file", b"x", None)])
put("pve", "tar_files", "normal", normal)
put("pve", "tar_files", "hostile", hostile)
put("pve", "ct_records", "ok", rec(b"C", b"arch: amd64\nhostname: ct200\n") + rec(b"D", normal[:700])
    + rec(b"D", b"") + rec(b"D", normal[700:]) + rec(b"E", b"ok"))
put("pve", "ct_records", "fail", rec(b"C", b"") + rec(b"D", b"x") + rec(b"E", b"fail tar failed (exit 2)"))
put("pve", "ct_records", "huge", rec(b"C", b"") + b"D\xff\xff\xff\xff")


def frames(data, step):
    out = b""
    for i in range(0, len(data), step):
        out += struct.pack(">I", len(data[i:i + step])) + data[i:i + step]
    return out + struct.pack(">I", 0)


put("pve", "agent_frames", "tar", frames(normal, 512) + b'{"ok":{"entries":5,"errors":[]}}\n')
put("pve", "agent_frames", "mounts", struct.pack(">I", 0) + json.dumps({"ok": [
    {"device": "/dev/vda1", "disk": "drive-scsi0", "fstype": "ext4", "label": None, "uuid": "u",
     "size": 1 << 30, "mountpoint": "/vda1", "error": None}]}).encode() + b"\n"
    + json.dumps({"ok": [{"name": "etc", "kind": "dir", "size": 4096, "mode": 16877, "mtime": 1, "uid": 0,
                          "gid": 0, "link": None}]}).encode() + b"\n" + b'{"err":"no such mount"}\n')
for i, r in enumerate([{"cmd": "mounts"}, {"cmd": "ls", "path": "/vda1/etc"}, {"cmd": "ls", "path": "/"},
                       {"cmd": "tar", "paths": ["/vda1/etc", "/lvm/vg0-root/home", "/zfs/tank+data/x"]},
                       {"cmd": "ls", "path": "/vda1/../etc"}, {"cmd": "ls", "path": "/zfs"}, {"cmd": "quit"}]):
    put("pve", "agent_request", f"req{i}", json.dumps(r) + "\n")

# ---------------------------------------------------------------- keyd
for i, l in enumerate(["acme\n", "ensure newtenant\n", "escrow acme\n", "ensure ../etc\n", "escrow .x\n",
                       "acme", "frob acme\n", "ensure " + "a" * 64 + "\n"]):
    put("keyd", "keyd_request", f"line{i}", l)
esc = b""
for n, d in [("kek.recovery", b"w" * 72), ("tenants/acme/dek.1", b"d" * 72)]:
    esc += struct.pack(">H", len(n)) + n.encode() + struct.pack(">I", len(d)) + d
put("keyd", "keyd_request", "escrow_answer", esc)

# ---------------------------------------------------------------- web-api
for i, s in enumerate(["acme-1.prod_x", ".hidden", "daily 23:59", "hourly 05", "vm-100", "ct-0100",
                       "/etc/passwd", "pve1.lab.local", "[fe80::1]", "security_officer",
                       '{"daily":7,"weekly":4,"monthly":12,"yearly":1}']):
    put("web-api", "validators", f"v{i}", s)

src = {"host": "pve1.lab.local", "port": 8006, "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
       "token_id": "nexus@pve!backup", "token_secret": "s", "nodes": {"pve1": {"host": "10.0.0.1"}},
       "storage": "local-lvm"}
calls = [
    (0, 0, "tenants", None), (0, 1, "tenants", {"name": "t1", "offsite": {}}),
    (0, 2, "tenants/acme", {"offsite": {"remote": "sftp"}}), (0, 3, "tenants/globex", None),
    (0, 1, "sources", {"tenant": "acme", "kind": "pve", "name": "pve", "config": src}),
    (0, 2, "sources/1", {"name": "pve", "config": src}), (0, 3, "sources/1", None),
    (0, 1, "policies", {"name": "p2", "schedule": "daily 01:30", "gfs": {"daily": 7, "weekly": 4, "monthly": 12, "yearly": 1}}),
    (0, 2, "policies/1", {"name": "std", "schedule": "daily 01:30", "gfs": {"daily": 1, "weekly": 4, "monthly": 12, "yearly": 1}, "offsite": False}),
    (0, 1, "groups", {"tenant": "acme", "source_id": 1, "policy_id": 1, "name": "g", "guests": [100, 101]}),
    (0, 2, "groups/1", {"source_id": 1, "policy_id": 2, "name": "g", "guests": [100]}), (0, 3, "groups/1", None),
    (0, 1, "users", {"name": "u1", "password": "correct horse battery", "role": "operator"}),
    (0, 2, "users/3", {"role": "admin", "tenant": None, "disabled": False}),
    (2, 1, "jobs", {"kind": "backup", "tenant": "acme", "params": {"vmid": 100}}),
    (3, 1, "jobs", {"kind": "files_get", "tenant": "acme", "params": {"source": "vm-100", "time": 1000, "paths": ["/vda1/etc"], "format": "zip"}}),
    (3, 1, "jobs", {"kind": "restore", "tenant": "acme", "params": {"source": "vm-100", "time": 1000, "node": "pve1", "target": 900, "storage": "local-lvm"}}),
    (2, 1, "jobs/1/cancel", {}), (2, 0, "jobs?state=queued&kind=backup&limit=5", None), (3, 0, "jobs/1", None),
    (1, 0, "quorum?state=pending", None), (1, 1, "quorum/1/approve", {}), (1, 1, "quorum/2/reject", {}),
    (1, 0, "audit?before=10&order=desc&limit=3", None), (1, 0, "audit/verify", None),
    (2, 0, "snapshots?tenant=acme&source=vm-100", None), (2, 0, "alerts?acked=false", None),
    (2, 1, "alerts/1/ack", {}), (3, 0, "downloads/" + "a" * 64, None), (5, 0, "metrics", None),
    (5, 1, "auth/logout", {}), (4, 0, "auth/me", None), (5, 0, "health", None), (4, 0, "sources", None),
]
for i, (who, m, path, body) in enumerate(calls):
    p = path.encode()
    put("web-api", "api_router", f"c{i}", bytes([who, m, len(p)]) + p + (json.dumps(body).encode() if body is not None else b""))
print("seeds written")
