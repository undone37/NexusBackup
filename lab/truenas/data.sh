#!/usr/bin/env bash
# Test data on the TrueNAS lab pool (run as truenas_admin via sh.py; uses sudo).
#   data.sh init     fresh tree: odd names, hardlinks, symlinks (incl. one to /), ACLs, xattrs,
#                    restricted dir, fifo, sparse + 64 MiB random file, 2000 small files
#   data.sh modify   round-2 changes: in-place edit, renames (file + dir), deletes, new files,
#                    new hardlink, chmod/chown, xattr-only and ACL-only changes
#   data.sh sums     sha256 of every regular file per dataset (for comparisons), sorted
#   data.sh xattrs   getfattr dump (hex) of every entry per dataset
set -euo pipefail
S="sudo -n"
# setx NAME VALUE FILE: setfattr, or Python's os.setxattr where the attr tools are missing (TrueNAS 27.0)
setx() {
  if command -v setfattr >/dev/null; then
    $S setfattr -n "$1" -v "$2" "$3"
  else
    $S python3 -c 'import os, sys; os.setxattr(sys.argv[3], sys.argv[1], sys.argv[2].encode())' "$1" "$2" "$3"
  fi
}
case "${1:-}" in
init)
  # a fresh start: no connector snapshots left from earlier runs
  for s in $(zfs list -H -t snapshot -o name -r tank | grep '@nexus-' || true); do $S zfs destroy "$s"; done
  for ds in data data/projects smb other; do
    $S find "/mnt/tank/$ds" -mindepth 1 -maxdepth 1 ! -name projects -exec rm -rf {} +
  done
  cd /mnt/tank/data
  $S mkdir -p docs big hl links secret many "dir with space" acl
  $S sh -c 'echo "hello truenas" > docs/readme.txt; printf "x%.0s" $(seq 1 5000) > docs/x.txt'
  $S sh -c 'echo umlaut > "docs/Grüße.txt"; echo nl > "docs/new
line"; echo bs > "docs/back\\slash"; echo dash > "docs/-dash"; echo tab > "docs/t	ab"'
  $S sh -c 'echo space > "dir with space/a b.txt"'
  $S dd if=/dev/urandom of=big/random.bin bs=1M count=64 status=none
  $S truncate -s 100M big/sparse.img
  $S sh -c 'echo "sparse tail" | dd of=big/sparse.img bs=1 seek=50000000 conv=notrunc status=none'
  $S sh -c 'echo linked > hl/a'; $S ln hl/a hl/b
  $S ln -s ../docs/readme.txt links/rel; $S ln -s / links/root; $S ln -s /etc/shadow links/shadow
  $S mkfifo links/fifo
  $S touch docs/empty
  $S sh -c 'echo topsecret > secret/key.txt'; $S chown -R 1234:1234 secret; $S chmod 700 secret; $S chmod 600 secret/key.txt
  setx user.comment "nexus test" docs/readme.txt
  $S sh -c 'echo acl > acl/file'; $S setfacl -m u:1001:rw acl/file; $S setfacl -d -m g:1002:rx acl
  $S chmod 4755 docs/x.txt
  $S bash -c 'for i in $(seq 1 2000); do echo "small $i" > many/f$i; done'
  $S touch -d '2001-02-03 04:05:06.123456789' docs/readme.txt
  cd /mnt/tank/data/projects
  $S mkdir -p p1; $S sh -c 'echo project > p1/plan.md; dd if=/dev/urandom of=p1/blob bs=1M count=3 status=none'
  cd /mnt/tank/smb
  $S mkdir -p share; $S sh -c 'echo smb > share/doc.txt'; $S chown 1001:1001 share/doc.txt
  $S nfs4xdr_setfacl -a 0 user:1001:rwx::allow share/doc.txt 2>/dev/null || $S nfs4xdr_setfacl -a 'user:1001:rwxpDdaARWcCos:-------:allow' share/doc.txt
  cd /mnt/tank/other; $S sh -c 'echo never > never.txt'
  ;;
modify)
  cd /mnt/tank/data
  $S sh -c 'echo "appended line" >> docs/x.txt'
  $S mv docs/readme.txt docs/README.txt
  $S mv many renamed-many
  $S sh -c 'echo changed > renamed-many/f7'
  $S rm docs/empty "docs/-dash"
  $S rm -r "dir with space"
  $S sh -c 'echo brand new > docs/new.txt'
  $S dd if=/dev/urandom of=big/random.bin bs=1M count=1 seek=10 conv=notrunc status=none
  $S ln docs/new.txt hl/new-link
  $S chmod 640 docs/x.txt; $S chown 1001:1001 "docs/Grüße.txt"
  setx user.comment "changed comment" docs/README.txt
  $S setfacl -m u:1003:r acl/file
  cd /mnt/tank/data/projects; $S sh -c 'echo v2 >> p1/plan.md'
  ;;
xattrs)
  # every xattr (incl. POSIX ACLs and system.nfs4_acl_xdr), hex, per dataset
  command -v getfattr >/dev/null || { echo "data.sh xattrs: no getfattr on this TrueNAS (27.0 dropped attr)" >&2; exit 1; }
  for ds in data data/projects smb; do
    echo "== $ds"
    (cd "/mnt/tank/$ds" && $S getfattr -R -P -d -m - -e hex . 2>/dev/null | grep -v '^$' || true)
  done
  ;;
sums)
  for ds in data data/projects smb; do
    echo "== $ds"
    (cd "/mnt/tank/$ds" && $S find . -type f -not -path './projects/*' -print0 | sort -z | $S xargs -0 sha256sum)
  done
  ;;
*) sed -n '2,8p' "$0"; exit 2 ;;
esac
