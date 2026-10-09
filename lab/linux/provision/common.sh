# Shared helpers for lab/linux/provision/*.sh (sourced as root inside the test VMs).
set -euo pipefail
DATA_DISK=/dev/disk/by-id/virtio-nexus-data
export DEBIAN_FRONTEND=noninteractive

say() { printf '== %s\n' "$*"; }

# sample tree with every kind of metadata the agent must keep: owners, modes
# (setuid, sticky), mtimes with nanoseconds, user xattrs, POSIX ACLs (access +
# default), file capabilities, hard links, symlinks, a fifo, a sparse file, odd
# names (UTF-8, spaces, a newline), big random files
mkdata() {
	local d=$1
	getent group nexuslab >/dev/null || groupadd -g 2001 nexuslab
	getent passwd alice >/dev/null || useradd -u 2001 -g 2001 -M -s /usr/sbin/nologin alice
	mkdir -p "$d"/{docs,bin,secret,shared,deep/a/b/c/d/e}
	for i in $(seq 1 200); do echo "line $i of $d" >"$d/docs/note-$i.txt"; done
	dd if=/dev/urandom of="$d/big.bin" bs=1M count=24 status=none
	dd if=/dev/urandom of="$d/medium.bin" bs=1M count=3 status=none
	truncate -s 64M "$d/sparse.img"
	printf 'head' | dd of="$d/sparse.img" conv=notrunc status=none
	printf 'tail' | dd of="$d/sparse.img" bs=1 seek=$((48 * 1024 * 1024)) conv=notrunc status=none
	: >"$d/empty"
	echo hard >"$d/hard-a"
	ln -f "$d/hard-a" "$d/hard-b"
	ln -sfn docs/note-1.txt "$d/link-rel"
	ln -sfn /etc/hostname "$d/link-abs"
	ln -sfn does-not-exist "$d/link-dangling"
	[ -p "$d/fifo" ] || mkfifo "$d/fifo"
	echo "Grüße" >"$d/Grüße mit Leerzeichen.txt"
	echo nl >"$d/new"$'\n'"line"
	echo deep >"$d/deep/a/b/c/d/e/file"
	cp /bin/true "$d/bin/suid-true"
	chmod 4755 "$d/bin/suid-true"
	chmod 1777 "$d/shared"
	echo secret >"$d/secret/key"
	chown -R alice:nexuslab "$d/secret"
	chmod 0700 "$d/secret"
	chmod 0640 "$d/secret/key"
	setfattr -n user.nexus -v hello "$d/docs/note-1.txt"
	setfattr -n user.binary -v 0x00ff00ff "$d/medium.bin"
	setfacl -m u:alice:rwx,g:nexuslab:r-x "$d/docs"
	setfacl -d -m u:alice:rw "$d/docs"
	setfacl -m u:alice:r "$d/big.bin"
	if command -v setcap >/dev/null; then
		cp /bin/true "$d/bin/cap-true"
		setcap cap_net_bind_service+ep "$d/bin/cap-true"
	fi
	touch -h -d '2001-02-03 04:05:06.123456789' "$d/docs/note-2.txt" "$d/link-rel"
	sync
}

# move an existing directory onto a freshly formatted device and mount it there (fstab)
move_onto() { # dir device fstype [opts]
	local dir=$1 dev=$2 fs=$3 opts=${4:-defaults}
	install -d /mnt/nexus-move
	mount "$dev" /mnt/nexus-move
	[ -d "$dir" ] && cp -a "$dir/." /mnt/nexus-move/
	umount /mnt/nexus-move
	mkdir -p "$dir"
	echo "$dev $dir $fs $opts 0 2" >>/etc/fstab
	systemctl daemon-reload
	mount "$dir"
}
