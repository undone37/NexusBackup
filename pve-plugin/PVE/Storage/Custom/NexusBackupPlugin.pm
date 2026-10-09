# SPDX-License-Identifier: AGPL-3.0-only
#
# NexusBackup storage plugin for Proxmox VE 9.x.
#
# Backup-only storage. All data lives on the NexusBackup appliance, which pulls
# it from the node over SSH (see docs/pve-connector.md). The node only keeps a
# catalog (index.json) pushed by the appliance. Nothing in this module makes a
# network connection.
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
        content => [{ backup => 1, none => 1 }, { backup => 1 }],
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

    die "unable to parse NexusBackup volume name '$volname'\n";
}

sub filesystem_path {
    my ($class, $scfg, $volname, $snapname) = @_;
    die "volume snapshots are not supported on NexusBackup storage\n" if $snapname;
    my (undef, $name, $vmid) = $class->parse_volname($volname);
    # Not a real file: the data lives on the appliance.
    my $path = "/var/lib/nexusbackup/archives/$name";
    return wantarray ? ($path, $vmid, 'backup') : $path;
}

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;
    return $class->filesystem_path($scfg, $volname, $snapname);
}

sub list_images {
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;
    return [];
}

sub list_volumes {
    my ($class, $storeid, $scfg, $vmid, $content_types) = @_;

    my $res = [];
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

sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase, $format) = @_;
    die $DELETE_MSG;
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
