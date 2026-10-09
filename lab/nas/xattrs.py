#!/usr/bin/env python3
"""Checks the xattrs/ACLs in a downloaded tar of a share against the server.

  xattrs.py DOWNLOAD.tar XATTRS(data.sh xattrs) nfs|smb

The tar carries xattrs as PAX `SCHILY.xattr.<name>` records (parsed here from
the raw blocks, values are binary). The server dump is `getfattr -d -m - -e hex`.
- nfs (NFS 4.2): every `user.*` xattr on the server is in the tar with the same
  value and vice versa; entries with a POSIX ACL on the server carry
  `system.nfs4_acl` (the server's NFSv4 view of it).
- smb: every `user.*` xattr in the tar (except the client's pseudo xattrs
  `user.cifs.*`) has the server's value; every regular file and directory
  carries `system.cifs_acl` (its security descriptor).
Samba's private server-side xattrs (user.DOSATTRIB, security.NTACL) are ignored.
"""
import sys

arc, dump, proto = sys.argv[1:4]


def pax(data):
    out = {}
    i = 0
    while i < len(data):
        sp = data.index(b" ", i)
        n = int(data[i:sp])
        rec = data[sp + 1:i + n - 1]
        k, v = rec.split(b"=", 1)
        out[k] = v
        i += n
    return out


def tar_xattrs(path):
    res = {}
    with open(path, "rb") as f:
        data = f.read()
    off, ext = 0, {}
    while off + 512 <= len(data):
        h = data[off:off + 512]
        if h == b"\0" * 512:
            break
        name = h[0:100].split(b"\0")[0]
        prefix = h[345:500].split(b"\0")[0]
        size = int(h[124:136].split(b"\0")[0].strip() or b"0", 8)
        typ = h[156:157]
        body = data[off + 512:off + 512 + size]
        off += 512 + (size + 511) // 512 * 512
        if typ == b"x":
            ext = pax(body)
            continue
        if typ == b"L":  # GNU long name
            ext[b"path"] = body.rstrip(b"\0")
            continue
        full = ext.get(b"path") or ((prefix + b"/" + name) if prefix else name)
        xa = {k[len(b"SCHILY.xattr."):].decode(): v for k, v in ext.items() if k.startswith(b"SCHILY.xattr.")}
        res[full.decode("utf-8", "surrogateescape").lstrip("/").rstrip("/")] = (typ, xa)
        ext = {}
    return res


def server_xattrs(path):
    res, cur = {}, None
    for line in open(path, encoding="utf-8", errors="surrogateescape"):
        line = line.rstrip("\n")
        if line.startswith("# file: "):
            cur = line[8:]
            cur = cur[2:] if cur.startswith("./") else ("" if cur == "." else cur)
            res[cur] = {}
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1)
            res[cur][k] = bytes.fromhex(v[2:]) if v.startswith("0x") else v.strip('"').encode()
    return res


tar = tar_xattrs(arc)
srv = server_xattrs(dump)
bad = 0
checked = 0
private = ("user.DOSATTRIB", "security.NTACL", "security.selinux")
for p, (typ, xa) in sorted(tar.items()):
    if proto == "smb" and p.startswith("links/"):
        continue  # symlinks: Samba serves the files they point to (with their xattrs)
    s = srv.get(p, {})
    for k, v in xa.items():
        if k.startswith("user.") and not k.startswith("user.cifs."):
            checked += 1
            if s.get(k) != v:
                print(f"{p}: {k} differs (tar {v[:24]!r}, server {s.get(k, b'')[:24]!r})")
                bad += 1
    if proto == "nfs":
        for k, v in s.items():
            if k.startswith("user.") and k not in private and xa.get(k) != v:
                print(f"{p}: server xattr {k} missing in the tar")
                bad += 1
        if "system.posix_acl_access" in s or "system.posix_acl_default" in s:
            checked += 1
            if "system.nfs4_acl" not in xa:
                print(f"{p}: has a POSIX ACL on the server but no system.nfs4_acl in the tar")
                bad += 1
    elif typ in (b"0", b"5"):
        checked += 1
        if "system.cifs_acl" not in xa:
            print(f"{p}: no system.cifs_acl")
            bad += 1
print(f"{arc}: {len(tar)} entries, {checked} xattr checks ({proto}), {bad} problems")
sys.exit(1 if bad else 0)
