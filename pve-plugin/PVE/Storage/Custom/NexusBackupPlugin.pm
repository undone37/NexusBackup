# SPDX-License-Identifier: AGPL-3.0-only
#
# NexusBackup storage plugin for Proxmox VE 9.x.
#
# Backup-only storage. All data lives on the NexusBackup appliance, which pulls
# it from the node over SSH (see docs/pve-connector.md). The node only keeps a
# catalog (index.json) pushed by the appliance, plus the qcow2 overlays of
# instant recovery volumes (ir/...). Nothing in this module makes a network
# connection.
package PVE::Storage::Custom::NexusBackupPlugin;

use strict;
use warnings;

use Fcntl qw(O_RDONLY);
use JSON;

use PVE::BackupProvider::Plugin::NexusBackup;

use base qw(PVE::Storage::Plugin);

# Fixed locations (contract). Package variables only so the unit tests can
# point them at a temporary directory; production code never changes them.
our $STATEDIR = '/var/lib/nexusbackup';
our $RUNDIR = '/run/nexusbackup/jobs';
our $RESTOREDIR = '/run/nexusbackup/restore';
our $GROUP = 'nexusbackup';
# Instant recovery: qcow2 overlays (root only) and the helper's NBD sockets
# that serve as their backing files.
our $IRDIR = '/var/lib/nexusbackup/ir';
our $IRRUNDIR = '/run/nexusbackup/ir';

my $INDEX_MAX = 64 * 1024 * 1024;
my $DEFAULT_JOB_TIMEOUT = 21600;
my $DELETE_MSG = "deletion is managed by the NexusBackup appliance\n";

# ---------------------------------------------------------------------------
# helpers shared with the backup provider

sub nexus_group_gid {
    my $gid = getgrnam($GROUP);
    die "group '$GROUP' does not exist (is nexusbackup-pve installed correctly?)\n"
        if !defined($gid);
    return $gid;
}

sub state_dir {
    my ($class, $storeid) = @_;
    return "$STATEDIR/$storeid";
}

sub job_timeout {
    my ($class, $scfg) = @_;
    return $scfg->{'nexus-job-timeout'} // $DEFAULT_JOB_TIMEOUT;
}

# Create /var/lib/nexusbackup/<storeid> (0770 root:nexusbackup) if missing.
# Never dies; used from activate_storage which pvestatd calls every few seconds.
sub ensure_state_dir {
    my ($class, $storeid) = @_;
    my $dir = $class->state_dir($storeid);
    return if -d $dir;
    eval {
        my $gid = nexus_group_gid();
        mkdir($STATEDIR, 0750) if !-d $STATEDIR;
        mkdir($dir, 0770) or die "mkdir $dir: $!\n";
        chown(-1, $gid, $dir);
        chmod(0770, $dir);
    };
    warn "nexusbackup: unable to create $dir: $@" if $@;
}

my $index_cache = {};

# Returns the parsed catalog as { archives => [ ... ], total => N, used => N }.
# Missing, oversized, unreadable or malformed index => empty catalog. Never dies.
sub read_index {
    my ($class, $storeid) = @_;

    my $empty = { archives => [], total => 0, used => 0 };
    my $file = $class->state_dir($storeid) . "/index.json";

    my @st = stat($file);
    return $empty if !@st;
    my $key = join(':', @st[0, 1, 7, 9]); # dev:ino:size:mtime
    my $cached = $index_cache->{$storeid};
    return $cached->{data} if $cached && $cached->{key} eq $key;

    my $data = eval {
        die "index too large\n" if $st[7] > $INDEX_MAX;
        sysopen(my $fh, $file, O_RDONLY) or die "open: $!\n";
        binmode($fh);
        local $/;
        my $raw = <$fh> // '';
        close($fh);
        my $json = JSON->new->utf8->decode($raw);
        die "not an object\n" if ref($json) ne 'HASH';
        $class->normalize_index($json);
    };
    if (my $err = $@) {
        warn "nexusbackup: ignoring unreadable index '$file': $err";
        $data = $empty;
    }

    $index_cache->{$storeid} = { key => $key, data => $data };
    return $data;
}

sub normalize_index {
    my ($class, $json) = @_;

    my $num = sub {
        my ($v) = @_;
        return (defined($v) && !ref($v) && $v =~ m/^\d+$/) ? $v + 0 : 0;
    };

    my $archives = [];
    for my $a (ref($json->{archives}) eq 'ARRAY' ? $json->{archives}->@* : ()) {
        next if ref($a) ne 'HASH';
        my $volname = $a->{volname} // next;
        next if ref($volname) || $volname !~ m!^backup/nexus-(\d+)-(\d+)$!;
        my ($vmid, $ctime) = ($1, $2);
        next if defined($a->{vmid}) && "$a->{vmid}" ne $vmid;
        my $devices = ref($a->{devices}) eq 'ARRAY' ? [grep { defined && !ref } $a->{devices}->@*] : [];
        my $device_sizes = {};
        if (ref($a->{device_sizes}) eq 'HASH') {
            for my $d (keys $a->{device_sizes}->%*) {
                next if $d !~ m/^[a-z0-9\-]{1,64}\z/;
                $device_sizes->{$d} = $num->($a->{device_sizes}->{$d});
            }
        }
        my $size = $num->($a->{size});
        if (%$device_sizes) {
            $size = 0;
            $size += $_ for values %$device_sizes;
        }
        push @$archives, {
            volname => $volname,
            vmid => $vmid + 0,
            # absent in catalogs from before container support: VM
            type => (($a->{type} // '') eq 'lxc' ? 'lxc' : 'qemu'),
            ctime => $num->($a->{ctime}) || $ctime + 0,
            size => $size,
            devices => $devices,
            device_sizes => $device_sizes,
            config => (defined($a->{config}) && !ref($a->{config})) ? $a->{config} : undef,
            firewall => (defined($a->{firewall}) && !ref($a->{firewall})) ? $a->{firewall} : undef,
            notes => (defined($a->{notes}) && !ref($a->{notes})) ? $a->{notes} : '',
            protected => ($a->{protected} ? 1 : 0),
        };
    }

    return { archives => $archives, total => $num->($json->{total}), used => $num->($json->{used}) };
}

sub find_archive {
    my ($class, $storeid, $volname) = @_;
    for my $a ($class->read_index($storeid)->{archives}->@*) {
        return $a if $a->{volname} eq $volname;
    }
    return undef;
}

# ---------------------------------------------------------------------------
# instant recovery volumes: ir/<vmid>/<archive>.<device>.qcow2
#
# A node-local qcow2 overlay owned by the target VM <vmid>. Its backing file is
# the appliance's read-only NBD export of <device>, reached through the
# helper's socket (ir-serve). Guest writes stay in the overlay until
# `qm disk move` copies the disk to real storage and frees the volume.

my $IR_VOLNAME_RE = qr!^ir/(\d{1,9})/((nexus-\d{1,9}-\d{1,12})\.([a-z0-9\-]{1,64})\.qcow2)\z!;
my $IR_FILE_RE = qr!^((nexus-\d{1,9}-\d{1,12})\.([a-z0-9\-]{1,64})\.qcow2)\z!;
# Seconds QEMU holds guest I/O while the appliance's export is unreachable
# (reconnect), and waits for a listener when opening the backing file.
our $IR_RECONNECT_DELAY = 60;
our $IR_OPEN_TIMEOUT = 60;

# Returns untainted ($vmid, $file, $archive, $device) or () if not an IR volume.
sub parse_ir_volname {
    my ($volname) = @_;
    return () if !defined($volname) || $volname !~ $IR_VOLNAME_RE;
    return ($1, $2, $3, $4);
}

sub untaint_storeid {
    my ($storeid) = @_;
    ($storeid) = ($storeid // '') =~ m/^([a-z][a-z0-9\-_.]{0,99})\z/i
        or die "invalid storage id\n";
    return $storeid;
}

sub ir_overlay_path {
    my ($class, $storeid, $vmid, $file) = @_;
    return "$IRDIR/" . untaint_storeid($storeid) . "/$vmid/$file";
}

# QEMU backing file spec of an overlay: raw over the helper's NBD socket.
sub ir_backing_spec {
    my ($class, $vmid, $archive, $device) = @_;
    my $spec = {
        driver => 'raw',
        file => {
            driver => 'nbd',
            server => { type => 'unix', path => "$IRRUNDIR/$vmid.$archive.$device.sock" },
            export => $device,
            'reconnect-delay' => $IR_RECONNECT_DELAY + 0,
            'open-timeout' => $IR_OPEN_TIMEOUT + 0,
        },
    };
    return 'json:' . JSON->new->canonical->encode($spec);
}

# Real directory owned by us, not writable by group/others; created 0700 if missing.
my $ensure_private_dir = sub {
    my ($dir) = @_;
    mkdir($dir, 0700) or $!{EEXIST} or die "mkdir $dir: $!\n";
    my @st = lstat($dir) or die "stat $dir: $!\n";
    die "$dir must be a directory owned by uid $> without group/other write access\n"
        if !-d _ || -l _ || $st[4] != $> || ($st[2] & 022);
};

# Creates the overlay if missing (root; called from activate_volume). The size
# comes from the catalog, the backing file only from the volume name.
sub ir_create_overlay {
    my ($class, $storeid, $vmid, $file, $archive, $device) = @_;

    my $path = $class->ir_overlay_path($storeid, $vmid, $file);
    my $sdir = "$IRDIR/" . untaint_storeid($storeid);
    $ensure_private_dir->($_) for ($IRDIR, $sdir, "$sdir/$vmid");

    if (lstat($path)) {
        die "instant recovery overlay '$path' is not a regular file\n" if !-f _ || -l _;
        return $path;
    }

    my $a = $class->find_archive($storeid, "backup/$archive")
        or die "archive '$archive' not found in NexusBackup catalog of '$storeid'\n";
    die "archive '$archive' is not a VM backup\n" if $a->{type} ne 'qemu';
    my $size = $class->ir_volume_size($storeid, $archive, $device);
    die "archive '$archive' has no device '$device'\n" if !$size;

    my $tmp = "$sdir/$vmid/.$file.$$.tmp";
    unlink($tmp);
    my @cmd = ('qemu-img', 'create', '-q', '-f', 'qcow2', '-u', '-F', 'raw',
        '-b', $class->ir_backing_spec($vmid, $archive, $device), $tmp, $size);
    if (system(@cmd) != 0) {
        my $code = $? >> 8;
        unlink($tmp);
        die "qemu-img create of '$path' failed (exit $code)\n";
    }
    rename($tmp, $path) or do { my $err = $!; unlink($tmp); die "rename to $path: $err\n" };
    return $path;
}

sub ir_volume_size {
    my ($class, $storeid, $archive, $device) = @_;
    my $a = $class->find_archive($storeid, "backup/$archive") or return undef;
    # untaint (perl -T): PVE passes it on to e.g. lvcreate when moving the disk
    my ($size) = ($a->{device_sizes}->{$device} // '') =~ m/^(\d{1,20})\z/;
    return $size;
}

# ---------------------------------------------------------------------------
# configuration

# Highest storage API version tested (PVE 9.2). Report the running version
# within the tested range to avoid "older storage API" warnings; fall back to 11.
use constant TESTED_APIVER => 14;

sub api {
    my $v = defined(&PVE::Storage::APIVER) ? PVE::Storage::APIVER() : 11;
    return ($v >= 11 && $v <= TESTED_APIVER) ? $v : 11;
}

sub type {
    return 'nexusbackup';
}

sub plugindata {
    return {
        # 'images' only for instant recovery overlays (alloc_image refuses)
        content => [{ backup => 1, images => 1, none => 1 }, { backup => 1 }],
        features => { 'backup-provider' => 1 },
        'sensitive-properties' => {},
    };
}

sub properties {
    return {
        'nexus-fleecing-storage' => {
            description => "Storage used for fleecing images during NexusBackup VM backups"
                . " (fast local thin storage). Used by the appliance when triggering vzdump.",
            type => 'string',
            format => 'pve-storage-id',
        },
        'nexus-job-timeout' => {
            description => "Seconds a VM backup waits for the NexusBackup appliance to finish"
                . " before failing.",
            type => 'integer',
            minimum => 60,
            default => $DEFAULT_JOB_TIMEOUT,
        },
    };
}

sub options {
    return {
        'nexus-fleecing-storage' => {},
        'nexus-job-timeout' => { optional => 1 },
        content => { optional => 1 },
        nodes => { optional => 1 },
        disable => { optional => 1 },
        'prune-backups' => { optional => 1 },
        'max-protected-backups' => { optional => 1 },
    };
}

sub on_add_hook {
    my ($class, $storeid, $scfg, %param) = @_;
    $class->ensure_state_dir($storeid);
    return undef;
}

# ---------------------------------------------------------------------------
# volumes

sub parse_volname {
    my ($class, $volname) = @_;

    if ($volname =~ m!^backup/(nexus-(\d+)-\d+)$!) {
        return ('backup', $1, $2, undef, undef, undef, 'nexus');
    }
    if (my ($vmid, $file) = parse_ir_volname($volname)) {
        return ('images', $file, $vmid, undef, undef, 0, 'qcow2');
    }

    die "unable to parse NexusBackup volume name '$volname'\n";
}

sub filesystem_path {
    my ($class, $scfg, $volname, $snapname) = @_;
    die "volume snapshots are not supported on NexusBackup storage\n" if $snapname;
    my ($vtype, $name, $vmid) = $class->parse_volname($volname);
    die "instant recovery volume path needs the storage id\n" if $vtype ne 'backup';
    # Not a real file: the data lives on the appliance.
    my $path = "/var/lib/nexusbackup/archives/$name";
    return wantarray ? ($path, $vmid, 'backup') : $path;
}

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;
    if (my ($vmid, $file) = parse_ir_volname($volname)) {
        die "volume snapshots are not supported on NexusBackup storage\n" if $snapname;
        my $path = $class->ir_overlay_path($storeid, $vmid, $file);
        return wantarray ? ($path, $vmid, 'images') : $path;
    }
    return $class->filesystem_path($scfg, $volname, $snapname);
}

# Instant recovery overlays present on this node.
sub list_images {
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;

    my $res = [];
    my $sdir = "$IRDIR/" . untaint_storeid($storeid);
    opendir(my $dh, $sdir) or return $res;
    for my $owner (sort readdir($dh)) {
        ($owner) = $owner =~ m/^(\d{1,9})\z/ or next; # untaint (perl -T)
        next if defined($vmid) && $owner != $vmid;
        opendir(my $vd, "$sdir/$owner") or next;
        for my $f (sort readdir($vd)) {
            my ($file, $archive, $device) = $f =~ $IR_FILE_RE or next;
            my $volid = "$storeid:ir/$owner/$file";
            next if $vollist && !grep { $_ eq $volid } @$vollist;
            my @st = stat("$sdir/$owner/$file") or next;
            push @$res, {
                volid => $volid,
                format => 'qcow2',
                vmid => $owner + 0,
                size => $class->ir_volume_size($storeid, $archive, $device) // 0,
                used => $st[12] * 512,
                ctime => $st[9],
            };
        }
        closedir($vd);
    }
    closedir($dh);
    return $res;
}

sub list_volumes {
    my ($class, $storeid, $scfg, $vmid, $content_types) = @_;

    my $res = [];
    if (grep { $_ eq 'images' } ($content_types // [])->@*) {
        push @$res, map { { $_->%*, content => 'images' } } $class->list_images($storeid, $scfg, $vmid)->@*;
    }
    return $res if !grep { $_ eq 'backup' } ($content_types // [])->@*;

    my $index = eval { $class->read_index($storeid) } // { archives => [] };
    for my $a ($index->{archives}->@*) {
        next if defined($vmid) && $a->{vmid} != $vmid;
        push @$res, {
            volid => "$storeid:$a->{volname}",
            vmid => $a->{vmid},
            format => 'nexus',
            ctime => $a->{ctime},
            size => $a->{size},
            subtype => $a->{type},
            content => 'backup',
            notes => $a->{notes},
            protected => $a->{protected},
        };
    }

    return $res;
}

sub volume_size_info {
    my ($class, $scfg, $storeid, $volname, $timeout) = @_;

    if (my ($vmid, $file, $archive, $device) = parse_ir_volname($volname)) {
        my $size = $class->ir_volume_size($storeid, $archive, $device);
        my $path = $class->ir_overlay_path($storeid, $vmid, $file);
        my @st = stat($path);
        if (!$size && @st && defined(&PVE::Storage::Plugin::file_size_info)) {
            # archive already gone from the catalog: ask the overlay itself
            # (qemu-img info does not open the backing file)
            $size = PVE::Storage::Plugin::file_size_info($path, $timeout, 'qcow2');
        }
        die "volume '$storeid:$volname' not found\n" if !$size;
        my $used = @st ? $st[12] * 512 : 0;
        return wantarray ? ($size, 'qcow2', $used, undef, @st ? $st[9] : undef) : $size;
    }

    $class->parse_volname($volname);
    my $a = $class->find_archive($storeid, $volname)
        or die "volume '$storeid:$volname' not found in NexusBackup catalog\n";

    return wantarray ? ($a->{size}, 'nexus', $a->{size}, undef, $a->{ctime}) : $a->{size};
}

sub get_volume_attribute {
    my ($class, $scfg, $storeid, $volname, $attribute) = @_;

    return undef if $attribute ne 'notes' && $attribute ne 'protected';
    my $a = $class->find_archive($storeid, $volname) or return undef;
    return $a->{$attribute};
}

sub update_volume_attribute {
    my ($class, $scfg, $storeid, $volname, $attribute, $value) = @_;
    die $DELETE_MSG;
}

# Only instant recovery overlays can be freed (qm disk move --delete, qm destroy);
# backups never.
sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase, $format) = @_;
    my ($vmid, $file) = parse_ir_volname($volname) or die $DELETE_MSG;
    my $path = $class->ir_overlay_path($storeid, $vmid, $file);
    unlink($path) or $!{ENOENT} or die "unable to delete '$path': $!\n";
    rmdir("$IRDIR/" . untaint_storeid($storeid) . "/$vmid"); # if empty
    return undef;
}

# Retention is the appliance's job. Must never die: vzdump calls this after
# every backup, and a die would fail a backup whose bitmap is already committed.
sub prune_backups {
    my ($class, $scfg, $storeid, $keep, $vmid, $type, $dryrun, $logfunc) = @_;

    my $res = [];
    eval {
        for my $v ($class->list_volumes($storeid, $scfg, $vmid, ['backup'])->@*) {
            next if defined($type) && $v->{subtype} ne $type;
            push @$res, {
                volid => $v->{volid},
                ctime => $v->{ctime},
                mark => 'keep',
                type => $v->{subtype},
                vmid => $v->{vmid},
            };
        }
    };
    eval { $logfunc->('info', "retention of '$storeid' is managed by the NexusBackup appliance") }
        if $logfunc;

    return $res;
}

# ---------------------------------------------------------------------------
# storage state (local only, cheap: pvestatd calls these every ~10 s)

sub status {
    my ($class, $storeid, $scfg, $cache) = @_;

    my $index = eval { $class->read_index($storeid) } // {};
    my $total = $index->{total} // 0;
    my $used = $index->{used} // 0;
    my $free = $total > $used ? $total - $used : 0;

    return ($total, $free, $used, 1);
}

sub check_connection {
    my ($class, $storeid, $scfg) = @_;
    return 1;
}

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;
    $class->ensure_state_dir($storeid);
    return 1;
}

sub deactivate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;
    return 1;
}

sub activate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;
    die "volume snapshots are not supported on NexusBackup storage\n" if $snapname;
    if (my ($vmid, $file, $archive, $device) = parse_ir_volname($volname)) {
        $class->ir_create_overlay($storeid, $vmid, $file, $archive, $device);
    }
    return 1;
}

sub deactivate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;
    return 1;
}

# ---------------------------------------------------------------------------
# image operations: not applicable to a backup-only storage

sub alloc_image {
    die "NexusBackup storage cannot hold disk images\n";
}

sub create_base {
    die "NexusBackup storage cannot hold disk images\n";
}

sub clone_image {
    die "NexusBackup storage cannot hold disk images\n";
}

sub volume_resize {
    die "NexusBackup storage cannot hold disk images\n";
}

sub volume_snapshot {
    die "volume snapshots are not supported on NexusBackup storage\n";
}

sub volume_snapshot_rollback {
    die "volume snapshots are not supported on NexusBackup storage\n";
}

sub volume_snapshot_delete {
    die "volume snapshots are not supported on NexusBackup storage\n";
}

sub volume_has_feature {
    return 0;
}

# ---------------------------------------------------------------------------
# backup provider

sub new_backup_provider {
    my ($class, $scfg, $storeid, $log_function) = @_;

    return PVE::BackupProvider::Plugin::NexusBackup->new($class, $scfg, $storeid, $log_function);
}

1;
