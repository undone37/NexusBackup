#!/usr/bin/env python3
"""Compares a downloaded tar/zip of a NAS share snapshot with lab/nas/data.sh sums.

  compare.py DOWNLOAD.tar|.zip SUMS SHARE [--smb] [--allow PATH]...   (SHARE: share or many)

Every regular file of the share (sha256) must be in the archive with the same
content; hard links count as their target (tar: link member, zip: stored as a
symlink to the first name). Exit 1 on any difference.

--smb: the share as an SMB client sees it. Samba cannot represent some Linux
names (backslash, colon, control characters, ...; it shows mangled 8.3 names)
and serves symlinks inside the share as the files they point to, so names it
cannot represent are not required and additional files are listed, not errors.
"""
import hashlib
import stat
import sys
import tarfile
import zipfile

arc, sums_file, ds = sys.argv[1:4]
smb = "--smb" in sys.argv[4:]
# --allow PATH: a known, documented difference (reported, not an error)
allow = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--allow"]


def smb_ok(p):
    return not any(c in p for c in '\\:*?"<>|') and not any(ord(c) < 32 for c in p) \
        and not any(part.endswith((" ", ".")) for part in p.split("/"))


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
skipped = []
if smb:
    skipped = sorted(p for p in want if not smb_ok(p))
    want = {p: h for p, h in want.items() if smb_ok(p)}
    for p in skipped:
        print(f"not representable over SMB (not required): {p!r}")
for p, h in sorted(want.items()):
    if got.get(p) != h and p in allow:
        print(f"known difference (allowed): {p!r}")
        continue
    if got.get(p) != h:
        print(f"differs: {p!r}: want {h[:12]}, got {str(got.get(p))[:12]}")
        bad += 1
# churn/ is rewritten continuously by `data.sh churn`: not in the sums
extra = sorted(p for p in set(got) - set(want) if not p.startswith("churn/"))
for p in extra:
    print(f"unexpected file in the download: {p!r}")
print(f"{arc}: {len(want)} files compared, {bad} differ, {len(extra)} unexpected"
      + (f" (SMB: {len(skipped)} names not representable, extras allowed)" if smb else ""))
sys.exit(1 if bad or (extra and not smb) else 0)
