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

# ---------------------------------------------------------------- truenas
# shapes of what the forced command returns (lab/truenas, TrueNAS 25.10.7)
put("truenas", "hostile_stream", "diff",
    "M\tF\t/mnt/tank/data/big/random.bin\n-\tF\t/mnt/tank/data/docs/empty\n"
    "R\tF\t/mnt/tank/data/many/f7\t/mnt/tank/data/renamed-many/f7\nM\t/\t/mnt/tank/data/\n"
    "-\t/\t/mnt/tank/data/dir\\0040with\\0040space\nM\tF\t/mnt/tank/data/docs/Gr\\0303\\0274\\0303\\0237e.txt\n"
    "M\tF\t/mnt/tank/data/docs/new.txt\t(+1)\n+\tF\t/mnt/tank/data/hl/new-link\n")


def walk_rec(head, path, link=b""):
    return head.encode() + b"\0" + path + b"\0" + link + b"\0"


put("truenas", "hostile_stream", "walk",
    walk_rec("d 755 0 0 4 1791569435.3239792120 1791569435.3239792120 129 2", b"d")
    + walk_rec("f 644 0 0 5 1791569435.3279792230 1791569435.3279792230 258 2", b"d/f")
    + walk_rec("f 644 0 0 5 1791569435.3279792230 1791569435.3279792230 258 2", b"d/hard")
    + walk_rec("l 777 0 0 1 1.0 1.0 300 1", b"d/root", b"/")
    + walk_rec("p 644 0 0 0 1.0 1.0 301 1", b"d/new\nline"))


def pax_tar(members):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, data, pax in members:
            ti = tarfile.TarInfo(name)
            ti.pax_headers = dict(pax)
            if data is None:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    return b.getvalue()


put("truenas", "hostile_stream", "tar",
    pax_tar([("d/", None, {"SCHILY.xattr.system.posix_acl_default": "\x02\0\0\0\x01\0\x07\0"}),
             ("d/f", b"hello", {"SCHILY.xattr.user.comment": "nexus test", "mtime": "1.5"})]))
put("truenas", "hostile_stream", "tar-hostile",
    pax_tar([("d/", None, {}), ("d/f", b"hello", {"path": "../../etc/shadow"})]))
# ---------------------------------------------------------------- nas
# requests the connector sends to nexus-nasmount (crates/nas/src/proto.rs)
def nas_req(*kv):
    return "nexus-nasmount 1\n" + "".join(f"{k} {v}\n" for k, v in kv) + "end\n"


put("nas", "helper_request", "nfs42",
    nas_req(("fs", "nfs"), ("host", "nas.lab"), ("addr", "10.0.2.2"), ("port", "12049"), ("version", "4.2"),
            ("sec", "sys"), ("timeout", "60"), ("export", "/srv/share"), ("mount_port", "20048")))
put("nas", "helper_request", "nfs3",
    nas_req(("fs", "nfs"), ("host", "fd00::5"), ("addr", "fd00::5"), ("port", "2049"), ("version", "3"),
            ("sec", "sys"), ("timeout", "30"), ("export", "/srv/many"), ("mount_port", "12048")))
put("nas", "helper_request", "smb",
    nas_req(("fs", "smb"), ("host", "fs1"), ("addr", "10.0.2.2"), ("port", "10445"), ("version", "3.1.1"),
            ("sec", "ntlmssp"), ("timeout", "60"), ("share", "Data Files"), ("user", "nexusbackup"),
            ("domain", "LAB"), ("sign", "1"), ("seal", "1"), ("password", "73332c63723d6574")))
put("nas", "helper_request", "krb5",
    nas_req(("fs", "smb"), ("host", "fs1.lab.example"), ("addr", "10.0.2.2"), ("port", "445"), ("version", "3"),
            ("sec", "krb5"), ("timeout", "60"), ("share", "share"), ("sign", "1"), ("seal", "0"),
            ("keytab", "0502000000"), ("principal", "backup@LAB.EXAMPLE")))
put("nas", "helper_request", "answer", "error nfs: access denied by server\n")

# ---------------------------------------------------------------- fsindex
# small images from the local tools (skipped if missing), cut to the fuzzer's
# max_len (64 KiB): headers, first directories, FAT/MFT starts; crafted
# partition tables, LVM metadata and helper frames
import shutil, subprocess, tempfile, zlib


def find_tool(name):
    return shutil.which(name) or next((p for p in (f"/usr/sbin/{name}", f"/sbin/{name}") if os.path.exists(p)), None)


def tool_img(size_kb, cmd, create=True, cut=65536):
    exe = find_tool(cmd[0])
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as d:
        img = os.path.join(d, "img")
        if create:
            with open(img, "wb") as f:
                f.truncate(size_kb * 1024)
        r = subprocess.run([exe] + [a.replace("IMG", img) for a in cmd[1:]], capture_output=True)
        if r.returncode != 0:
            return None
        with open(img, "rb") as f:
            return f.read(cut)


for target, name, kb, cmd, create in [
    ("ext4_walk", "ext2-1k", 64, ["mke2fs", "-q", "-F", "-t", "ext2", "-b", "1024", "-N", "16", "IMG"], True),
    ("ext4_walk", "ext4-1k", 64,
     ["mke2fs", "-q", "-F", "-t", "ext4", "-b", "1024", "-N", "16", "-O", "^has_journal,^resize_inode", "IMG"], True),
    ("fat_walk", "fat12", 64, ["mkfs.fat", "-C", "IMG", "64"], False),
    ("exfat_walk", "exfat", 4096, ["mkfs.exfat", "IMG"], True),
    ("ntfs_walk", "ntfs", 2048, ["mkntfs", "-F", "-Q", "-q", "IMG"], True),
]:
    data = tool_img(kb, cmd, create)
    if data:
        put("fsindex", target, name, data)
        put("fsindex", "disk_walk", name, data)


def gpt_disk(sectors=128):
    d = bytearray(sectors * 512)
    d[446 + 4] = 0xee
    d[446 + 8:446 + 16] = struct.pack("<II", 1, sectors - 1)
    d[510:512] = b"\x55\xaa"
    arr = bytearray(128 * 4)
    arr[0:16] = bytes.fromhex("79d3d6e607f5c244a23c238f2a3df928")
    arr[16:32] = b"\x11" * 16
    arr[32:48] = struct.pack("<QQ", 34, 100)
    h = bytearray(92)
    h[0:8] = b"EFI PART"
    h[12:16] = struct.pack("<I", 92)
    h[40:56] = struct.pack("<QQ", 34, sectors - 2)
    h[72:80] = struct.pack("<Q", 2)
    h[80:88] = struct.pack("<II", 4, 128)
    h[88:92] = struct.pack("<I", zlib.crc32(bytes(arr)))
    h[16:20] = struct.pack("<I", zlib.crc32(bytes(h)))
    d[512:604] = h
    d[1024:1024 + len(arr)] = arr
    return bytes(d)


def mbr_disk():
    d = bytearray(64 * 1024)

    def ent(s, i, t, lba, n):
        s[446 + i * 16 + 4] = t
        s[446 + i * 16 + 8:446 + i * 16 + 16] = struct.pack("<II", lba, n)

    ent(d, 0, 0x83, 8, 20)
    ent(d, 1, 0x05, 40, 80)
    d[510:512] = b"\x55\xaa"
    e1 = bytearray(512)
    ent(e1, 0, 0x8e, 2, 10)
    ent(e1, 1, 0x05, 20, 30)
    e1[510:512] = b"\x55\xaa"
    d[40 * 512:41 * 512] = e1
    e2 = bytearray(512)
    ent(e2, 0, 0x07, 2, 10)
    e2[510:512] = b"\x55\xaa"
    d[60 * 512:61 * 512] = e2
    return bytes(d)


for n, data in [("gpt", gpt_disk()), ("mbr-ebr", mbr_disk())]:
    put("fsindex", "part_table", n, data)
    put("fsindex", "disk_walk", n, data)

LVM_TEXT = """vg0 {
id = "Vg0Id1-aaaa-bbbb-cccc-dddd-eeee-ffffff"
seqno = 7
status = ["RESIZEABLE", "READ", "WRITE"]
extent_size = 8192
physical_volumes {
pv0 { id = "AAAAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAAA" device = "/dev/vda2" pe_start = 2048 pe_count = 100 }
pv1 { id = "BBBBBB-BBBB-BBBB-BBBB-BBBB-BBBB-BBBBBB" device = "/dev/vdb" pe_start = 2048 pe_count = 100 }
}
logical_volumes {
root { id = "r" status = ["READ", "WRITE", "VISIBLE"] segment_count = 2
segment1 { start_extent = 0 extent_count = 10 type = "striped" stripe_count = 1 stripes = ["pv0", 0] }
segment2 { start_extent = 10 extent_count = 4 type = "striped" stripe_count = 2 stripe_size = 128 stripes = ["pv0", 10, "pv1", 0] } }
m { id = "m" status = ["READ", "WRITE", "VISIBLE"]
segment1 { start_extent = 0 extent_count = 2 type = "raid1" device_count = 2 raids = ["m_rmeta_0", "m_rimage_0", "m_rmeta_1", "m_rimage_1"] } }
m_rimage_0 { id = "x" status = ["READ"] segment1 { start_extent = 0 extent_count = 2 type = "striped" stripe_count = 1 stripes = ["pv1", 50] } }
}
}
contents = "Text Format Volume Group"
version = 1
"""


def lvm_crc(b):
    c = 0xf597a6cf
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    return c


def pv_disk(text):
    d = bytearray(16 * 1024)
    lab = bytearray(512)
    lab[0:8] = b"LABELONE"
    lab[8:16] = struct.pack("<Q", 1)
    lab[20:24] = struct.pack("<I", 32)
    lab[24:32] = b"LVM2 001"
    lab[32:64] = b"A" * 32
    lab[72:80] = struct.pack("<Q", 1 << 20)
    lab[104:120] = struct.pack("<QQ", 4096, 12288)
    lab[16:20] = struct.pack("<I", lvm_crc(lab[20:512]))
    d[512:1024] = lab
    h = bytearray(512)
    h[4:20] = b" LVM2 x[5A%r0N*>"
    h[20:24] = struct.pack("<I", 1)
    h[24:40] = struct.pack("<QQ", 4096, 12288)
    h[40:56] = struct.pack("<QQ", 512, len(text))
    h[0:4] = struct.pack("<I", lvm_crc(h[4:512]))
    d[4096:4608] = h
    d[4608:4608 + len(text)] = text.encode()
    return bytes(d)


put("fsindex", "lvm_meta", "text", LVM_TEXT)
put("fsindex", "lvm_meta", "pv", pv_disk(LVM_TEXT))
put("fsindex", "disk_walk", "pv", pv_disk(LVM_TEXT))


def fx_frame(tag, payload):
    return tag + struct.pack("<I", len(payload)) + payload


def fx_ent(path, kind=0, size=5, mtime=1700000000):
    p = path.encode()
    return bytes([kind]) + struct.pack("<QqH", size, mtime, len(p)) + p


vol_json = json.dumps({"key": "drive-scsi0@0+1", "browse": "vda1", "device": "drive-scsi0", "fs": "ext4",
                       "size": 1, "state": "indexed"}).encode()
put("fsindex", "helper_frames", "listing",
    fx_frame(b"B", vol_json) + fx_frame(b"E", fx_ent("etc", 1) + fx_ent("etc/hosts")) + fx_frame(b"Z", vol_json)
    + fx_frame(b"Q", b""))
put("fsindex", "helper_frames", "hostile",
    fx_frame(b"B", vol_json.replace(b"vda1", b"../x")) + fx_frame(b"E", fx_ent("../etc/passwd") + fx_ent("/abs")))


def hive(keys):
    """A minimal registry hive (as crates/fsindex/src/regf.rs `build`): the root key with
    one subkey per (name, [(value name, type, data)])."""
    bins = bytearray(b"hbin" + bytes(28))

    def cell(data):
        off = len(bins)
        n = (len(data) + 4 + 7) // 8 * 8
        bins.extend(struct.pack("<i", -n) + data)
        bins.extend(bytes(off + n - len(bins)))
        return off

    def key(name, subs, values):
        lst = cell(b"lf" + struct.pack("<H", len(subs)) + b"".join(struct.pack("<II", s, 0) for s in subs)) if subs else 0
        vl = cell(b"".join(struct.pack("<I", v) for v in values)) if values else 0
        k = bytearray(0x4c)
        k[0:4] = b"nk" + struct.pack("<H", 0x20)
        struct.pack_into("<I", k, 0x14, len(subs))
        struct.pack_into("<I", k, 0x1c, lst)
        struct.pack_into("<II", k, 0x24, len(values), vl)
        struct.pack_into("<H", k, 0x48, len(name))
        return cell(bytes(k) + name.encode())

    def value(name, ty, data):
        if len(data) <= 4:
            size, at = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\0"))[0]
        else:
            size, at = len(data), cell(data)
        return cell(b"vk" + struct.pack("<HIIIHH", len(name), size, at, ty, 1, 0) + name.encode())

    subs = [key(n, [], [value(*v) for v in vals]) for n, vals in keys]
    root = key("ROOT", subs, [])
    size = (len(bins) + 4095) // 4096 * 4096
    bins.extend(bytes(size - len(bins)))
    struct.pack_into("<I", bins, 8, size)
    base = bytearray(4096)
    base[0:4] = b"regf"
    struct.pack_into("<IIIIII", base, 4, 1, 1, 0, 0, 1, 5)
    struct.pack_into("<II", base, 36, root, size)
    x = 0
    for i in range(127):
        x ^= struct.unpack_from("<I", base, i * 4)[0]
    struct.pack_into("<I", base, 508, {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(x, x))
    return bytes(base + bins)


def dmio(g):
    return b"DMIO:ID:" + __import__("uuid").UUID(g).bytes_le


put("fsindex", "regf_hive", "system", hive([
    ("Select", [("Current", 4, struct.pack("<I", 1))]),
    ("MountedDevices", [("\\DosDevices\\C:", 3, dmio("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")),
                        ("\\DosDevices\\E:", 3, struct.pack("<IQ", 0xdeadbeef, 1 << 20)),
                        ("\\??\\Volume{x}", 3, "\\??\\SCSI#CdRom".encode("utf-16-le"))]),
]))


def xfs_seed(extra):
    """The first 64 KiB of a small XFS (1 KiB blocks, external log: the root inode chunk lies
    within them) holding a few directories and files."""
    exe = find_tool("mkfs.xfs")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as d:
        img, log, src, proto = (os.path.join(d, n) for n in ("img", "log", "src", "proto"))
        for p, n in ((img, 32 << 20), (log, 16 << 20)):
            with open(p, "wb") as f:
                f.truncate(n)
        with open(src, "wb") as f:
            f.write(b"x" * 1500)
        lines = ["/dev/null", "0 0", "d--755 0 0", "etc d--755 0 0", f"fstab ---644 0 0 {src}", "$",
                 "home d--755 0 0"] + [f"f{i} ---644 0 0 {src}" for i in range(12)] + ["$",
                 "link l--777 0 0 etc/fstab", "$"]
        with open(proto, "w") as f:
            f.write("\n".join(lines) + "\n")
        env = dict(os.environ, QA_CHECK_FS="1", TEST_DIR="1", TEST_DEV="1")
        r = subprocess.run([exe, "-q", "-b", "size=1024", "-d", "agcount=1", "-l", f"logdev={log},size=10m",
                            "-p", proto] + extra + [img], capture_output=True, env=env)
        if r.returncode != 0:
            return None
        with open(img, "rb") as f:
            return f.read(65536)


for name, extra in [("v5-1k", []), ("v4-1k", ["-m", "crc=0", "-n", "ftype=0", "-i", "size=256"])]:
    data = xfs_seed(extra)
    if data:
        put("fsindex", "xfs_walk", name, data)
        put("fsindex", "disk_walk", "xfs-" + name, data)


def crc32c_raw(data, c=0xFFFFFFFF):
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    return c


def thin_node(blk, leaf, kv, mx=252):
    b = bytearray(4096)
    struct.pack_into("<IQIII", b, 4, 2 if leaf else 1, blk, len(kv), mx, 8)
    for i, (k, v) in enumerate(kv):
        struct.pack_into("<Q", b, 32 + i * 8, k)
        struct.pack_into("<Q", b, 32 + mx * 8 + i * 8, v)
    struct.pack_into("<I", b, 0, crc32c_raw(b[4:]) ^ 121107)
    return bytes(b)


def thin_meta(maps, block_sectors=128):
    """dm-thin pool metadata as crates/fsindex/tests/images.rs `thin_metadata` writes it."""
    sb = bytearray(4096)
    struct.pack_into("<QI", sb, 32, 27022010, 2)
    struct.pack_into("<Q", sb, 320, 1)
    struct.pack_into("<II", sb, 336, block_sectors, 8)
    struct.pack_into("<I", sb, 0, crc32c_raw(sb[4:]) ^ 160774)
    vals = [(v, d << 24 | 5) for v, d in maps]
    a, b = vals[:len(vals) // 2], vals[len(vals) // 2:]
    return (bytes(sb) + thin_node(1, True, [(1, 2)]) + thin_node(2, False, [(a[0][0], 3), (b[0][0], 4)])
            + thin_node(3, True, a) + thin_node(4, True, b))


put("fsindex", "lvm_thin", "pool", thin_meta([(0, 5), (1, 6), (2, 7), (9, 1), (10, 0), (40, 3)]))

print("seeds written")
