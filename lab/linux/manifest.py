#!/usr/bin/env python3
"""Metadata manifest of a directory tree for restore comparisons (lab/linux/e2e.sh).

    manifest.py DIR            one line per entry, sorted, paths relative to DIR

Per entry: kind, permission bits (incl. setuid/sticky), uid, gid, size, mtime in ns,
sha256 (regular files), link target (symlinks), device numbers, hard-link group (the
first path of the group), every xattr (user.*, security.capability, POSIX ACLs as
system.posix_acl_*; security.selinux and XFS's trusted.SGI_ACL_* are left out: a restore target may get a
different label by policy). Not compared: atime, ctime, inode numbers.
"""
import hashlib
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
# XFS shows its on-disk ACLs to root as trusted.SGI_ACL_*: duplicates of system.posix_acl_*
SKIP_XATTRS = {b"security.selinux", b"trusted.SGI_ACL_FILE", b"trusted.SGI_ACL_DEFAULT"}


def esc(b):
    return b.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)


paths = []
for d, dirs, files in os.walk(root):
    for n in dirs + files:
        paths.append(os.path.join(d, n))
paths.sort()
links = {}
out = []
for p in paths:
    rel = os.path.relpath(p, root)
    st = os.lstat(p)
    m = st.st_mode
    kind = {stat.S_IFREG: "f", stat.S_IFDIR: "d", stat.S_IFLNK: "l", stat.S_IFIFO: "p",
            stat.S_IFCHR: "c", stat.S_IFBLK: "b", stat.S_IFSOCK: "s"}[stat.S_IFMT(m)]
    f = [kind, "%04o" % stat.S_IMODE(m), str(st.st_uid), str(st.st_gid)]
    if kind != "d":
        f.append("mtime=%d" % st.st_mtime_ns)
    if kind == "f":
        f += ["size=%d" % st.st_size, sha256(p)]
        if st.st_nlink > 1:
            f.append("link=" + esc(links.setdefault((st.st_dev, st.st_ino), rel)))
    elif kind == "l":
        f.append("-> " + esc(os.readlink(p)))
    elif kind in "cb":
        f.append("dev=%d,%d" % (os.major(st.st_rdev), os.minor(st.st_rdev)))
    try:
        names = sorted(n.encode() for n in os.listxattr(p, follow_symlinks=False))
    except OSError:
        names = []
    for n in names:
        if n in SKIP_XATTRS:
            continue
        f.append("x:%s=%s" % (n.decode(), os.getxattr(p, n, follow_symlinks=False).hex()))
    out.append(esc(rel) + "\t" + " ".join(f))
print("\n".join(out))
