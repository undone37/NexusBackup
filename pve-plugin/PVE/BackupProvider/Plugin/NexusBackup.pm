# SPDX-License-Identifier: AGPL-3.0-only
#
# NexusBackup backup provider for Proxmox VE 9.x (pull model).
#
# backup_vm publishes the NBD export of the running backup as a job file in
# /run/nexusbackup/jobs/ and blocks until the appliance, connected over SSH
# through /usr/lib/nexusbackup/helper, has read the data, committed the
# snapshot and written <vmid>.done. See docs/pve-connector.md.
package PVE::BackupProvider::Plugin::NexusBackup;

use strict;
use warnings;

use Fcntl qw(O_WRONLY O_CREAT O_EXCL);
use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Path qw(make_path);
use JSON;

use base qw(PVE::BackupProvider::Plugin::Base);

my $UNSUPPORTED_CT = "NexusBackup: container backups are not supported in v1\n";
my $UNSUPPORTED_CT_RESTORE = "NexusBackup: container restore is not supported\n";

sub new {
    my ($class, $storage_plugin, $scfg, $storeid, $log_function) = @_;

    my $self = bless {
        'storage-plugin' => $storage_plugin,
        scfg => $scfg,
        storeid => $storeid,
        'log-function' => $log_function,
        archive => {},
        'backup-vm-ok' => {},
        'archive-size' => {},
    }, $class;

    return $self;
}

sub _log {
    my ($self, $level, $msg) = @_;
    chomp($msg);
    eval { $self->{'log-function'}->($level, $msg) };
    print STDERR "$level: $msg\n" if $@;
}

sub plugin { $_[0]->{'storage-plugin'} }

sub rundir {
    no warnings 'once';
    return $PVE::Storage::Custom::NexusBackupPlugin::RUNDIR;
}

sub provider_name {
    return 'NexusBackup';
}

sub job_init {
    my ($self, $start_time) = @_;

    $self->{'job-start'} = $start_time;

    # tmpfiles.d normally creates it; recreate if somebody removed it.
    my $gid = PVE::Storage::Custom::NexusBackupPlugin::nexus_group_gid();
    ensure_rendezvous_dir($self->rundir(), $gid);

    return;
}

# /run/nexusbackup/<x>: 1770 root:nexusbackup. Sticky: the helper (group
# member) may create files there but cannot replace or remove root's files.
sub ensure_rendezvous_dir {
    my ($dir, $gid) = @_;
    return if -d $dir;
    make_path(dirname($dir), { mode => 0750 });
    chown(-1, $gid, dirname($dir));
    mkdir($dir) or die "unable to create $dir: $!\n";
    chown(-1, $gid, $dir) or die "unable to chown $dir: $!\n";
    chmod(01770, $dir) or die "unable to chmod $dir: $!\n";
}

sub job_cleanup {
    my ($self) = @_;
    return;
}

sub backup_init {
    my ($self, $vmid, $vmtype, $start_time) = @_;

    my $name = "nexus-${vmid}-${start_time}";
    $self->{archive}->{$vmid} = $name;
    $self->{'backup-vm-ok'}->{$vmid} = 0;

    return { 'archive-name' => $name };
}

sub backup_get_mechanism {
    my ($self, $vmid, $vmtype) = @_;

    return 'nbd' if $vmtype eq 'qemu';
    die $UNSUPPORTED_CT;
}

sub backup_vm_query_incremental {
    my ($self, $vmid, $volumes) = @_;

    my %known;
    my $index = eval { $self->plugin()->read_index($self->{storeid}) } // { archives => [] };
    for my $a ($index->{archives}->@*) {
        next if $a->{vmid} != $vmid;
        $known{$_} = 1 for $a->{devices}->@*;
    }

    my $res = {};
    for my $device (keys %$volumes) {
        $res->{$device} = $known{$device} ? 'use' : 'new';
    }
    return $res;
}

my $write_atomic = sub {
    my ($path, $content, $gid) = @_;

    my $tmp = "$path.tmp.$$";
    unlink($tmp);
    sysopen(my $fh, $tmp, O_WRONLY | O_CREAT | O_EXCL, 0640) or die "unable to create $tmp: $!\n";
    eval {
        chown(-1, $gid, $tmp) or die "unable to chown $tmp: $!\n";
        chmod(0640, $tmp) or die "unable to chmod $tmp: $!\n";
        binmode($fh);
        print {$fh} $content or die "unable to write $tmp: $!\n";
        close($fh) or die "unable to close $tmp: $!\n";
        rename($tmp, $path) or die "unable to rename $tmp to $path: $!\n";
    };
    if (my $err = $@) {
        unlink($tmp);
        die $err;
    }
};

sub backup_vm {
    my ($self, $vmid, $guest_config, $volumes, $info) = @_;

    $self->{'backup-vm-ok'}->{$vmid} = 0;

    my $archive = $self->{archive}->{$vmid} // die "backup_vm called before backup_init\n";
    my $gid = PVE::Storage::Custom::NexusBackupPlugin::nexus_group_gid();
    my $dir = $self->rundir();
    my $job_file = "$dir/$vmid.json";
    my $done_file = "$dir/$vmid.done";
    my $sock_link = "$dir/$vmid.nbd";

    my $cleanup = sub { unlink($job_file, $done_file, $sock_link) };

    $cleanup->(); # stale files from an earlier, crashed job

    eval {
        die "no volumes to back up\n" if !%$volumes;

        my %paths = map { ($_->{'nbd-path'} // '') => 1 } values %$volumes;
        my @paths = keys %paths;
        die "expected exactly one NBD socket, got: " . join(', ', @paths) . "\n"
            if @paths != 1 || $paths[0] eq '';
        my $nbd_path = $paths[0];
        $nbd_path =~ s!/+!/!g;
        die "NBD socket '$nbd_path' does not exist\n" if !-S $nbd_path;

        # The socket lives under /run/qemu-server (0750 root:www-data) in a 0700
        # directory. Give group nexusbackup rw on the socket inode and publish it
        # through a hard link in the rendezvous dir (same tmpfs), so neither
        # qemu-server directory has to be opened up.
        my $mode = (stat($nbd_path))[2] & 07777;
        chown(-1, $gid, $nbd_path) or die "unable to chgrp $nbd_path: $!\n";
        chmod($mode | 0060, $nbd_path) or die "unable to chmod $nbd_path: $!\n";
        link($nbd_path, $sock_link) or die "unable to link $nbd_path to $sock_link: $!\n";

        my $devices = [];
        for my $name (sort keys %$volumes) {
            my $v = $volumes->{$name};
            push @$devices, {
                name => $name,
                size => $v->{size} + 0,
                bitmap_mode => $v->{'bitmap-mode'} // 'none',
                bitmap_name => $v->{'bitmap-name'},
            };
            $self->_log('info', "device $name: size $v->{size}, bitmap-mode "
                . ($v->{'bitmap-mode'} // 'none'));
        }

        my $total = 0;
        $total += $_->{size} for @$devices;
        $self->{'archive-size'}->{$vmid} = $total;

        my $job = {
            vmid => $vmid + 0,
            archive => $archive,
            nbd_socket => $sock_link,
            devices => $devices,
            config => $guest_config,
            firewall => $info->{'firewall-config'},
        };

        $write_atomic->($job_file, JSON->new->utf8->canonical->encode($job) . "\n", $gid);

        $self->_log('warn', "bandwidth limit is not enforced by the node, the appliance applies"
            . " its own limits") if $info->{'bandwidth-limit'};

        my $timeout = $self->plugin()->job_timeout($self->{scfg});
        $self->_log('info', "published job $archive, waiting for the NexusBackup appliance"
            . " (timeout ${timeout}s)");

        my $start = time();
        my $next_note = $start + 300;
        while (1) {
            if (-e $done_file) {
                open(my $fh, '<', $done_file) or die "unable to read $done_file: $!\n";
                my $content = do { local $/; <$fh> } // '';
                close($fh);
                $content =~ s/\s+$//;
                if ($content eq 'ok') {
                    last;
                } elsif ($content =~ m/^fail(?:\s+(.*))?$/s) {
                    my $msg = $1 // 'no reason given';
                    die "NexusBackup appliance reported failure: $msg\n";
                } else {
                    die "invalid content in $done_file\n";
                }
            }
            my $now = time();
            die "timeout after ${timeout}s waiting for the NexusBackup appliance\n"
                if $now - $start >= $timeout;
            if ($now >= $next_note) {
                $self->_log('info', "still waiting for the NexusBackup appliance ("
                    . ($now - $start) . "s)");
                $next_note = $now + 300;
            }
            # Signals (task abort) interrupt sleep; vzdump's handler then dies.
            sleep(1);
        }
    };
    my $err = $@;
    $cleanup->();
    die $err if $err;

    $self->{'backup-vm-ok'}->{$vmid} = 1;
    $self->_log('info', "NexusBackup appliance committed $archive");
    return;
}

sub backup_cleanup {
    my ($self, $vmid, $vmtype, $success, $info) = @_;

    if (!$success && defined($vmid) && $self->{'backup-vm-ok'}->{$vmid}) {
        # The appliance already committed the snapshot and QEMU commits the
        # bitmap regardless of later failures; the snapshot stays valid.
        $self->_log('warn', "backup failed after the appliance committed the snapshot"
            . " $self->{archive}->{$vmid}; the snapshot is kept: "
            . ($info->{error} // 'unknown error'));
    }

    return {} if !$success;
    return { stats => { 'archive-size' => $self->{'archive-size'}->{$vmid} // 0 } };
}

sub backup_handle_log_file {
    my ($self, $vmid, $filename) = @_;

    my $archive = $self->{archive}->{$vmid} or return;
    eval {
        my $gid = PVE::Storage::Custom::NexusBackupPlugin::nexus_group_gid();
        my $dir = $self->plugin()->state_dir($self->{storeid}) . "/logs";
        if (!-d $dir) {
            make_path($dir, { mode => 0750 });
            chown(-1, $gid, $dir);
        }
        my $target = "$dir/$archive.log";
        copy($filename, "$target.tmp") or die "copy failed: $!\n";
        chown(-1, $gid, "$target.tmp");
        chmod(0640, "$target.tmp");
        rename("$target.tmp", $target) or die "rename failed: $!\n";
    };
    $self->_log('warn', "unable to store task log: $@") if $@;
    return;
}

sub backup_container_prepare {
    die $UNSUPPORTED_CT;
}

sub backup_container {
    die $UNSUPPORTED_CT;
}

sub archive_get_guest_config {
    my ($self, $volname, $storeid) = @_;

    my $a = $self->plugin()->find_archive($self->{storeid}, $volname)
        or die "archive '$volname' not found in NexusBackup catalog\n";
    die "archive '$volname' has no guest configuration\n" if !defined($a->{config});
    return $a->{config};
}

sub archive_get_firewall_config {
    my ($self, $volname, $storeid) = @_;

    my $a = $self->plugin()->find_archive($self->{storeid}, $volname)
        or die "archive '$volname' not found in NexusBackup catalog\n";
    return $a->{firewall};
}

# ---------------------------------------------------------------------------
# VM restore (docs/pve-connector.md "VM restore flow"): the appliance serves each
# device over SSH (helper restore-serve) on a unix socket in the restore dir;
# the node attaches it read-only to /dev/nbdX with its own qemu-nbd.

sub restoredir {
    no warnings 'once';
    return $PVE::Storage::Custom::NexusBackupPlugin::RESTOREDIR;
}

sub restore_get_mechanism {
    my ($self, $volname) = @_;
    return ('qemu-img', 'qemu');
}

sub restore_vm_init {
    my ($self, $volname) = @_;

    my $a = $self->plugin()->find_archive($self->{storeid}, $volname)
        or die "archive '$volname' not found in NexusBackup catalog\n";
    my $sizes = $a->{device_sizes};
    die "catalog entry for '$volname' has no device sizes\n" if !%$sizes;

    return { map { ($_ => { size => $sizes->{$_} }) } keys %$sizes };
}

our $SYSBLOCK = '/sys/block'; # tests only

my $nbd_size = sub {
    my ($dev) = @_;
    open(my $fh, '<', "$SYSBLOCK/$dev/size") or return undef;
    my $v = <$fh>;
    close($fh);
    chomp($v) if defined($v);
    return $v;
};

sub restore_vm_volume_init {
    my ($self, $volname, $device, $info) = @_;

    die "invalid device name '$device'\n" if $device !~ m/^[a-z0-9\-]{1,64}\z/;
    my (undef, $archive) = $self->plugin()->parse_volname($volname);
    my $gid = PVE::Storage::Custom::NexusBackupPlugin::nexus_group_gid();
    my $dir = $self->restoredir();
    ensure_rendezvous_dir($dir, $gid);

    my $json = "$dir/$archive.json";
    my $sock = "$dir/$archive.$device.sock";
    unlink($sock);

    my $req = { archive => $archive, device => $device, socket => $sock };
    $write_atomic->($json, JSON->new->utf8->canonical->encode($req) . "\n", $gid);

    my $timeout = $self->plugin()->job_timeout($self->{scfg});
    $self->_log('info', "restore of $device requested, waiting for the NexusBackup appliance"
        . " (timeout ${timeout}s)");

    my $nbd;
    eval {
        my $start = time();
        while (!-S $sock) {
            die "timeout after ${timeout}s waiting for the NexusBackup appliance\n"
                if time() - $start >= $timeout;
            sleep(1);
        }

        system('modprobe', 'nbd') if !-e "$SYSBLOCK/nbd0";
        die "no /dev/nbd* devices (modprobe nbd failed?)\n" if !-e "$SYSBLOCK/nbd0";

        opendir(my $dh, $SYSBLOCK) or die "unable to list $SYSBLOCK: $!\n";
        my @devs = sort { ($a =~ s/\D//gr) <=> ($b =~ s/\D//gr) } grep { m/^nbd\d+$/ } readdir($dh);
        closedir($dh);
        for my $d (@devs) {
            next if -e "$SYSBLOCK/$d/pid" || ($nbd_size->($d) // 1) != 0;
            $nbd = $d;
            last;
        }
        die "no free /dev/nbd* device\n" if !$nbd;

        my @cmd = ('qemu-nbd', '-c', "/dev/$nbd", '-r', '--image-opts',
            "driver=raw,file.driver=nbd,file.server.type=unix,file.server.path=$sock,"
            . "file.export=$device");
        system(@cmd) == 0 or die "qemu-nbd -c /dev/$nbd failed (exit " . ($? >> 8) . ")\n";
        $self->{restore}->{$volname}->{$device} = "/dev/$nbd";

        for (1 .. 100) {
            last if ($nbd_size->($nbd) // 0) > 0;
            select(undef, undef, undef, 0.1);
        }
        die "/dev/$nbd has no size after attaching\n" if !($nbd_size->($nbd) // 0);
    };
    if (my $err = $@) {
        eval { $self->restore_vm_volume_cleanup($volname, $device, $info) };
        die $err;
    }

    $self->_log('info', "attached $device as /dev/$nbd");
    return { 'qemu-img-path' => "/dev/$nbd" };
}

sub restore_vm_volume_cleanup {
    my ($self, $volname, $device, $info) = @_;

    my (undef, $archive) = $self->plugin()->parse_volname($volname);
    my $dir = $self->restoredir();
    if (my $dev = delete $self->{restore}->{$volname}->{$device}) {
        system('qemu-nbd', '-d', $dev) == 0
            or $self->_log('warn', "qemu-nbd -d $dev failed (exit " . ($? >> 8) . ")");
    }
    unlink("$dir/$archive.json", "$dir/$archive.$device.sock");
    return;
}

sub restore_vm_cleanup {
    my ($self, $volname) = @_;

    for my $device (keys %{ $self->{restore}->{$volname} // {} }) {
        eval { $self->restore_vm_volume_cleanup($volname, $device, {}) };
    }
    delete $self->{restore}->{$volname};
    my (undef, $archive) = eval { $self->plugin()->parse_volname($volname) };
    if (defined($archive)) {
        my $dir = $self->restoredir();
        unlink(glob("$dir/$archive.json $dir/$archive.*.sock"));
    }
    return;
}

sub restore_container_init { die $UNSUPPORTED_CT_RESTORE }
sub restore_container_cleanup { return }

1;
