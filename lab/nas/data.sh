#!/usr/bin/env bash
# Test data on the NAS lab VM (root; lab/nas/vm.sh data <cmd>).
#   data.sh init           fresh /srv/share: odd names, deep tree, symlinks (incl. to / and /etc/shadow),
#                          hard links, POSIX ACLs, user xattrs, root-only + foreign-owned files, fifo,
#                          sparse (1 GiB apparent) + 64 MiB random file, 2000 small files, old mtimes
#   data.sh many [N]       N (1000000) small files (64..4096 bytes, deterministic) in /srv/many/dNN/dNNN/fNNNN
#   data.sh modify         round-2 changes in /srv/share (edits, renames, deletes, new files, hard link,
#                          chmod/chown, xattr-only + ACL-only changes, same-size edit with mtime reset)
#   data.sh many-modify    /srv/many: change 1000, add 1000, delete 1000 files
#   data.sh sums [share|many]  sha256 of every regular file ("== <name>" header, ./relative paths)
#   data.sh churn [secs]   background writer on /srv/share/churn (live.log, big.bin 32 MiB); churn-stop
#   data.sh snap NAME      LVM snapshot of nas/share mounted read-only at /srv/share/.snapshot/NAME; snap-rm NAME
#   data.sh xattrs         getfattr dump (hex) of /srv/share
set -euo pipefail
SHARE=/srv/share
MANY=/srv/many

sums() {
	local name=$1 root=$2
	echo "== $name"
	(cd "$root" && find . -type f -not -path './.snapshot/*' -not -path './churn/*' -print0 | sort -z | xargs -0 -r sha256sum)
}

case "${1:-}" in
init)
	getent group nexuslab >/dev/null || groupadd -g 2001 nexuslab
	getent passwd alice >/dev/null || useradd -u 2001 -g 2001 -M -s /usr/sbin/nologin alice
	find "$SHARE" -mindepth 1 -maxdepth 1 ! -name lost+found ! -name .snapshot -exec rm -rf {} +
	cd "$SHARE"
	mkdir -p docs big hl hl2 links secret small "dir with space" acl owners churn .snapshot
	echo "hello nas" >docs/README.txt
	printf 'x%.0s' $(seq 1 5000) >docs/x.txt
	echo umlaut >"docs/Übergröße – 日本語.txt"
	echo nl >"docs/new"$'\n'"line"
	echo bs >'docs/back\slash'
	echo dash >docs/-dash
	echo tab >"docs/t"$'\t'"ab"
	echo space >"dir with space/a b.txt"
	: >docs/empty
	d=deep
	for i in $(seq 1 40); do d=$d/l$i; done
	mkdir -p "$d"
	echo "depth 40" >"$d/bottom.txt"
	dd if=/dev/urandom of=big/random.bin bs=1M count=64 status=none
	truncate -s 1G big/sparse.img
	dd if=/dev/urandom of=big/sparse.img bs=1M count=2 seek=100 conv=notrunc status=none
	echo "sparse tail" | dd of=big/sparse.img bs=1 seek=$((900 * 1024 * 1024)) conv=notrunc status=none
	echo linked >hl/a
	ln hl/a hl/b
	ln hl/a hl2/c
	ln -s ../docs/README.txt links/rel
	ln -s / links/root
	ln -s /etc/shadow links/shadow
	ln -s does-not-exist links/dangling
	mkfifo links/fifo
	echo topsecret >secret/key.txt
	chmod 700 secret
	chmod 600 secret/key.txt
	echo rootonly >docs/rootonly.txt
	chmod 600 docs/rootonly.txt
	echo foreign >owners/u1234.txt
	chown 1234:5678 owners/u1234.txt
	echo alice >owners/alice.txt
	chown alice:nexuslab owners/alice.txt
	chmod 640 owners/alice.txt
	chown 1234:5678 owners
	setfattr -n user.comment -v "nexus test" docs/README.txt
	setfattr -n user.dir -v "dir xattr" docs
	setfattr -n user.bin -v 0x00ff10 big/random.bin
	echo acl >acl/file
	setfacl -m u:1001:rw,g:1002:r acl/file
	setfacl -m u:1003:rx acl
	setfacl -d -m g:1002:rx acl
	chmod 4755 docs/x.txt
	for i in $(seq 1 2000); do echo "small $i" >small/f$i; done
	touch -d '2001-02-03 04:05:06.123456789' docs/README.txt
	touch -d '2010-01-01 00:00:00' docs/x.txt small
	echo "share initialised: $(find "$SHARE" -xdev | wc -l) entries"
	;;
many)
	n=${2:-1000000}
	have=$(find "$MANY" -xdev -type f 2>/dev/null | wc -l)
	if [ "$have" = "$n" ]; then
		echo "many: $n files already present"
		exit 0
	fi
	find "$MANY" -mindepth 1 -maxdepth 1 ! -name lost+found -exec rm -rf {} +
	t0=$(date +%s.%N)
	python3 - "$MANY" "$n" <<-'PY'
		import os, random, sys
		root, n = sys.argv[1], int(sys.argv[2])
		for i in range(n):
		    a, b, c = i // 100000, (i // 1000) % 100, i % 1000
		    d = os.path.join(root, f"d{a:02d}", f"d{b:03d}")
		    if c == 0:
		        os.makedirs(d, exist_ok=True)
		    r = random.Random(i)
		    with open(os.path.join(d, f"f{c:04d}"), "wb") as f:
		        f.write(r.randbytes(r.randint(64, 4096)))
	PY
	sync
	t1=$(date +%s.%N)
	echo "many: $n files in $(python3 -c "print(round($t1-$t0,1))") s, $(du -sh "$MANY" | cut -f1)"
	;;
modify)
	cd "$SHARE"
	# same size, new content and mtime
	echo "small X" >small/f1
	dd if=/dev/urandom of=big/random.bin bs=1M count=1 seek=10 conv=notrunc status=none
	mv docs/README.txt docs/README.md
	mv "dir with space" "renamed dir"
	rm docs/empty docs/-dash small/f2000
	echo "brand new" >docs/new.txt
	mkdir -p newdir
	echo "new in new dir" >newdir/n.txt
	ln docs/new.txt hl/new-link
	chmod 640 docs/x.txt
	chown 1001:1001 "docs/Übergröße – 日本語.txt"
	setfattr -n user.comment -v "changed comment" docs/README.md
	setfacl -m u:1004:r acl/file
	# same size + mtime reset: only ctime (and content) changed
	old=$(stat -c %y small/f3)
	echo "small Y" >small/f3
	touch -m -d "$old" small/f3
	echo "share modified"
	;;
many-modify)
	python3 - "$MANY" <<-'PY'
		import os, random, sys
		root = sys.argv[1]
		ch = add = rm = 0
		for k in range(1000):
		    i = k * 997
		    a, b, c = i // 100000, (i // 1000) % 100, i % 1000
		    p = os.path.join(root, f"d{a:02d}", f"d{b:03d}", f"f{c:04d}")
		    with open(p, "ab") as f:
		        f.write(b"changed\n"); ch += 1
		    # repeatable: a later round re-creates what an earlier one deleted and vice versa
		    q = os.path.join(root, f"d{a:02d}", f"d{b:03d}", f"f{(c + 1) % 1000:04d}")
		    n = os.path.join(root, f"d{a:02d}", f"d{b:03d}", f"new{k:04d}")
		    if os.path.exists(q):
		        os.unlink(q); rm += 1
		    else:
		        with open(q, "wb") as f:
		            f.write(random.Random(k).randbytes(700)); add += 1
		    if os.path.exists(n):
		        os.unlink(n); rm += 1
		    else:
		        with open(n, "wb") as f:
		            f.write(random.Random(-k).randbytes(512)); add += 1
		print(f"many: {ch} changed, {add} added, {rm} deleted")
	PY
	;;
sums)
	case "${2:-share}" in
	share) sums share "$SHARE" ;;
	many) sums many "$MANY" ;;
	*) echo "sums share|many" >&2; exit 2 ;;
	esac
	;;
churn)
	secs=${2:-600}
	mkdir -p "$SHARE/churn"
	[ -f "$SHARE/churn/big.bin" ] || dd if=/dev/urandom of="$SHARE/churn/big.bin" bs=1M count=32 status=none
	nohup bash -c "end=\$((SECONDS + $secs)); while [ \$SECONDS -lt \$end ]; do
		date +%s.%N >> $SHARE/churn/live.log
		dd if=/dev/urandom of=$SHARE/churn/big.bin bs=64K count=1 seek=\$((RANDOM % 512)) conv=notrunc status=none
		sleep 0.05; done" >/dev/null 2>&1 &
	echo $! >/run/nexus-churn.pid
	echo "churn running (pid $!, ${secs}s)"
	;;
churn-stop)
	[ -f /run/nexus-churn.pid ] && kill "$(cat /run/nexus-churn.pid)" 2>/dev/null || true
	rm -f /run/nexus-churn.pid
	echo "churn stopped"
	;;
snap)
	name=${2:?snap NAME}
	[[ $name =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad name" >&2; exit 2; }
	lvs "nas/snap-$name" >/dev/null 2>&1 || lvcreate -q -y -s -L 2G -n "snap-$name" nas/share
	mkdir -p "$SHARE/.snapshot/$name"
	mountpoint -q "$SHARE/.snapshot/$name" || mount -o ro,noload "/dev/nas/snap-$name" "$SHARE/.snapshot/$name"
	# the snapshot has the origin's file system UUID, so nfsd would give it the parent's
	# fsid (clients see ELOOP): export it explicitly with its own fsid (crossmnt reaches it)
	fsid=$((1000 + $(printf '%s' "$name" | cksum | cut -d' ' -f1) % 1000000))
	exportfs -o "ro,all_squash,anonuid=0,anongid=0,insecure,no_subtree_check,fsid=$fsid" "*:$SHARE/.snapshot/$name"
	echo "snapshot $name mounted at $SHARE/.snapshot/$name"
	;;
snap-rm)
	name=${2:?snap-rm NAME}
	exportfs -u "*:$SHARE/.snapshot/$name" 2>/dev/null || true
	exportfs -f
	mountpoint -q "$SHARE/.snapshot/$name" && umount "$SHARE/.snapshot/$name"
	rmdir "$SHARE/.snapshot/$name" 2>/dev/null || true
	lvs "nas/snap-$name" >/dev/null 2>&1 && lvremove -q -y "nas/snap-$name"
	echo "snapshot $name removed"
	;;
xattrs)
	echo "== share"
	(cd "$SHARE" && getfattr -R -P -h -d -m - -e hex . 2>/dev/null | grep -v '^$' || true)
	;;
*) sed -n '2,14p' "$0"; exit 2 ;;
esac
