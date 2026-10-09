#!/usr/bin/env python3
"""Compares a downloaded tar/zip of a TrueNAS dataset snapshot with `data.sh sums`.

  compare.py DOWNLOAD.tar|.zip SUMS DATASET     (DATASET as in the sums headers, e.g. data)

Every regular file of the dataset (sha256) must be in the archive with the same
content; hard links count as their target (tar: link member, zip: stored as a
symlink to the first name). Exit 1 on any difference.
"""
import hashlib
import stat
import sys
import tarfile
import zipfile

arc, sums_file, ds = sys.argv[1:4]


def unescape(p):
    return p.replace("\\\\", "\0").replace("\\n", "\n").replace("\0", "\\")


want = {}
cur = None
for line in open(sums_file, encoding="utf-8", errors="surrogateescape").read().splitlines():
    if line.startswith("== "):
        cur = line[3:]
        continue
    if cur != ds:
        continue
    esc = line.startswith("\\")
    h, p = (line[1:] if esc else line).split("  ./", 1)
    want[unescape(p) if esc else p] = h

got = {}
links = {}
if arc.endswith(".tar"):
    with tarfile.open(arc) as t:
        for m in t:
            if m.isfile():
                got[m.name] = hashlib.sha256(t.extractfile(m).read()).hexdigest()
            elif m.islnk():
                links[m.name] = m.linkname
else:
    with zipfile.ZipFile(arc) as z:
        for i in z.infolist():
            mode = i.external_attr >> 16
            data = z.read(i) if not i.is_dir() else b""
            if stat.S_ISLNK(mode):
                links[i.filename] = data.decode("utf-8", "surrogateescape")
            elif not i.is_dir():
                got[i.filename] = hashlib.sha256(data).hexdigest()
for name, target in links.items():
    if target in got:  # hard link (symlinks point elsewhere and are not in the sums)
        got[name] = got[target]

bad = 0
for p, h in sorted(want.items()):
    if got.get(p) != h:
        print(f"differs: {p!r}: want {h[:12]}, got {str(got.get(p))[:12]}")
        bad += 1
extra = sorted(set(got) - set(want))
for p in extra:
    print(f"unexpected file in the download: {p!r}")
print(f"{arc}: {len(want)} files compared, {bad} differ, {len(extra)} unexpected")
sys.exit(1 if bad or extra else 0)
