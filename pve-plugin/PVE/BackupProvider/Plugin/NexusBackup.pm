# SPDX-License-Identifier: AGPL-3.0-only
#
# NexusBackup backup provider for Proxmox VE 9.x (pull model).
#
# backup_vm publishes the NBD export of the running backup as a job file in
# /run/nexusbackup/jobs/ and blocks until the appliance, connected over SSH
# through /usr/lib/nexusbackup/helper, has read the data, committed the
# snapshot and written <vmid>.done. backup_container streams the container as
# one tar archive over a socket prepared by backup_container_prepare. See
# docs/pve-connector.md.
package PVE::BackupProvider::Plugin::NexusBackup;

use strict;
use warnings;

use Fcntl qw(O_WRONLY O_CREAT O_EXCL);
use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Path qw(make_path);
use IO::Select;
use IO::Socket::UNIX;
use JSON;
use Socket qw(SOCK_STREAM SHUT_WR);

use base qw(PVE::BackupProvider::Plugin::Base);

# Staging area for container restores (root only; holds container-relative
# uids, i.e. real root-owned setuid files, so it must never be world-reachable).
our $STAGEDIR = '/var/tmp/nexusbackup';

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
    $self->ct_cleanup($_) for keys %{ $self->{ct} // {} };
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
    return 'directory' if $vmtype eq 'lxc';
    die "NexusBackup: unsupported guest type '$vmtype'\n";
}

sub backup_vm_query_incremental {
    my ($self, $vmid, $volumes) = @_;

    my %known;
    my $index = eval { $self->plugin()->read_index($self->{storeid}) } // { archives => [] };
    for my $a ($index->{archives}->@*) {
        next if $a->{vmid} != $vmid || $a->{type} ne 'qemu';
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

    if (defined($vmid) && $self->{ct}->{$vmid}) {
        if (defined(my $size = $self->ct_cleanup($vmid))) {
            # the child reports the size only after the appliance committed
            $self->{'archive-size'}->{$vmid} = $size;
            $self->{'backup-vm-ok'}->{$vmid} = 1;
        }
    }

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

# ---------------------------------------------------------------------------
# Container backup (docs/pve-connector.md "Container backup flow").
#
# backup_container runs as the container's mapped root inside its user
# namespace, in a forked child, and cannot traverse /run/nexusbackup. So the
# privileged backup_container_prepare creates the listening socket (group
# nexusbackup, 0660) and the job file; the child inherits the listening fd,
# accepts the helper's `ct-stream` connection and sends records
# (tag byte, u32 big-endian length, payload):
#   'C' pct.conf (once, first), 'D' tar data (repeated), 'E' "ok" | "fail <msg>".
# The appliance answers on the same connection with one line "ok" or
# "fail <msg>" after it committed (or discarded) the snapshot.

my $CT_RECORD_MAX = 1024 * 1024;

my $ct_socket = sub {
    my ($self, $vmid) = @_;
    return $self->rundir() . "/$vmid.ct.sock";
};

sub backup_container_prepare {
    my ($self, $vmid, $info) = @_;

    ($vmid) = "$vmid" =~ m/^(\d{1,9})\z/ or die "invalid vmid\n";
    my $archive = $self->{archive}->{$vmid} // die "backup_container_prepare called before backup_init\n";
    my $gid = PVE::Storage::Custom::NexusBackupPlugin::nexus_group_gid();
    my $dir = $self->rundir();
    my $sock = $ct_socket->($self, $vmid);

    $self->ct_cleanup($vmid); # stale state from an earlier, crashed job
    $self->{'archive-size'}->{$vmid} = 0;
    $self->{'backup-vm-ok'}->{$vmid} = 0;

    eval {
        my $listen = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $sock, Listen => 1)
            or die "unable to listen on $sock: $!\n";
        my $ct = $self->{ct}->{$vmid} = { listen => $listen };
        chown(-1, $gid, $sock) or die "unable to chgrp $sock: $!\n";
        chmod(0660, $sock) or die "unable to chmod $sock: $!\n";
        # the forked child reports the stream size back through this pipe
        pipe($ct->{'size-r'}, $ct->{'size-w'}) or die "pipe: $!\n";

        my $job = {
            type => 'lxc',
            vmid => $vmid + 0,
            archive => $archive,
            socket => $sock,
            firewall => $info->{'firewall-config'},
        };
        $write_atomic->("$dir/$vmid.json", JSON->new->utf8->canonical->encode($job) . "\n", $gid);
    };
    if (my $err = $@) {
        $self->ct_cleanup($vmid);
        die $err;
    }

    $self->_log('warn', "bandwidth limit is not enforced by the node, the appliance applies"
        . " its own limits") if $info->{'bandwidth-limit'};
    $self->_log('info', "published container job $archive, waiting for the NexusBackup appliance"
        . " (timeout " . $self->plugin()->job_timeout($self->{scfg}) . "s)");
    return;
}

# Closes the listening socket and removes job file and socket (root, parent).
# Returns the stream size reported by the child, if any.
sub ct_cleanup {
    my ($self, $vmid) = @_;

    my $ct = delete $self->{ct}->{$vmid};
    my $size;
    if ($ct) {
        close($ct->{listen}) if $ct->{listen};
        if ($ct->{'size-r'}) {
            close($ct->{'size-w'});
            my $line = readline($ct->{'size-r'});
            close($ct->{'size-r'});
            ($size) = ($line // '') =~ m/^(\d{1,20})$/;
        }
    }
    my $dir = $self->rundir();
    unlink("$dir/$vmid.json", $ct_socket->($self, $vmid));
    return $size;
}

# GNU tar command line for the container stream, mirroring PVE's own vzdump
# tar invocation (exclude semantics, mount point sources). Pure; untaints.
sub ct_tar_command {
    my ($info, $exclude_patterns) = @_;

    my ($dir) = ($info->{directory} // '') =~ m!^(/[^\0\n]*)\z! or die "invalid backup directory\n";
    my @sources = map {
        m!^(\.(?:/[^\0\n]*)?)\z! ? $1 : die "invalid backup source\n"
    } ($info->{sources} // ['.'])->@*;
    @sources = ('.') if !@sources;

    my (@floating, @anchored);
    for my $p (($exclude_patterns // [])->@*) {
        my ($pat) = "$p" =~ m/^([^\0\n]{1,4096})\z/ or die "invalid exclude pattern\n";
        if ($pat =~ m!^/!) {
            push @anchored, "--exclude=.$pat";
        } else {
            push @floating, "--exclude=$pat";
        }
    }

    my @cmd = ('tar', '--create', '--file=-', '--numeric-owner', '--xattrs', '--xattrs-include=*',
        '--acls', '--sparse', '--one-file-system', '--preserve-permissions',
        '--warning=no-file-ignored', "--directory=$dir", '--no-anchored');
    # unprivileged: lost+found is 0700 real root and unreadable for the mapped root
    push @cmd, '--exclude=lost+found' if ($info->{'backup-user-id'} // 0) != 0;
    push @cmd, @floating, '--anchored', @anchored, '--', @sources;
    return \@cmd;
}

my $write_all = sub {
    my ($fh, $data, $what) = @_;
    my $off = 0;
    while ($off < length($data)) {
        my $w = syswrite($fh, $data, length($data) - $off, $off);
        if (!defined($w)) {
            next if $!{EINTR};
            die "write to $what failed: $!\n";
        }
        $off += $w;
    }
};

my $send_record = sub {
    my ($fh, $tag, $payload) = @_;
    $write_all->($fh, $tag . pack('N', length($payload)) . $payload, 'the NexusBackup appliance');
};

# Waits until $fh is readable; dies after $deadline (epoch seconds).
my $wait_readable = sub {
    my ($fh, $deadline, $what) = @_;
    my $sel = IO::Select->new($fh);
    while (1) {
        my $left = $deadline - time();
        die "timeout waiting for $what\n" if $left <= 0;
        return if $sel->can_read($left);
    }
};

sub backup_container {
    my ($self, $vmid, $guest_config, $exclude_patterns, $info) = @_;

    my $ct = $self->{ct}->{$vmid} or die "backup_container called before backup_container_prepare\n";
    my $timeout = $self->plugin()->job_timeout($self->{scfg});
    my $deadline = time() + $timeout;
    local $SIG{PIPE} = 'IGNORE';

    my $cmd = ct_tar_command($info, $exclude_patterns);

    $wait_readable->($ct->{listen}, $deadline, "the NexusBackup appliance (${timeout}s)");
    my $conn = $ct->{listen}->accept() or die "accept failed: $!\n";
    close($ct->{listen});
    binmode($conn);

    $send_record->($conn, 'C', $guest_config // '');

    my $pid = open(my $tar, '-|', @$cmd) or die "unable to run tar: $!\n";
    binmode($tar);
    my ($buf, $total) = ('', 0);
    eval {
        while (1) {
            my $n = sysread($tar, $buf, $CT_RECORD_MAX);
            if (!defined($n)) {
                next if $!{EINTR};
                die "read from tar failed: $!\n";
            }
            last if $n == 0;
            $send_record->($conn, 'D', $buf);
            $total += $n;
        }
    };
    if (my $err = $@) {
        kill('TERM', $1) if "$pid" =~ m/^(\d+)\z/; # untaint (perl -T)
        close($tar);
        die $err;
    }
    close($tar);
    my $status = $?;
    if ($status != 0) {
        my $msg = "tar failed (exit " . ($status >> 8) . ", signal " . ($status & 127) . ")";
        eval { $send_record->($conn, 'E', "fail $msg") };
        die "$msg\n";
    }
    $send_record->($conn, 'E', 'ok');

    # the appliance commits the snapshot, then answers
    my $answer = '';
    while ($answer !~ m/\n/) {
        $wait_readable->($conn, $deadline, "the NexusBackup appliance to commit");
        my $n = sysread($conn, $answer, 4096, length($answer));
        if (!defined($n)) {
            next if $!{EINTR};
            die "read from the NexusBackup appliance failed: $!\n";
        }
        die "NexusBackup appliance closed the connection without committing\n" if $n == 0;
        die "invalid answer from the NexusBackup appliance\n" if length($answer) > 2048;
    }
    close($conn);
    $answer =~ s/\n.*//s;
    if ($answer =~ m/^fail(?:\s+(.*))?$/s) {
        die "NexusBackup appliance reported failure: " . ($1 // 'no reason given') . "\n";
    }
    die "invalid answer from the NexusBackup appliance\n" if $answer ne 'ok';

    print { $ct->{'size-w'} } "$total\n";
    close($ct->{'size-w'});
    $self->_log('info', "NexusBackup appliance committed $self->{archive}->{$vmid} ($total bytes)");
    return;
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
    my $a = $self->plugin()->find_archive($self->{storeid}, $volname);
    return ('directory', 'lxc') if $a && $a->{type} eq 'lxc';
    return ('qemu-img', 'qemu');
}

sub restore_vm_init {
    my ($self, $volname) = @_;

    my $a = $self->plugin()->find_archive($self->{storeid}, $volname)
        or die "archive '$volname' not found in NexusBackup catalog\n";
    my $sizes = $a->{device_sizes};
    die "catalog entry for '$volname' has no device sizes\n" if !%$sizes;

    # API workers run with perl -T: catalog data is tainted and the sizes reach
    # lvcreate, so untaint by strict capture.
    my $res = {};
    for my $dev (keys %$sizes) {
        my ($d) = $dev =~ m/^([a-z0-9\-]{1,64})\z/ or die "invalid device name in catalog\n";
        my ($size) = ($sizes->{$dev} // '') =~ m/^(\d{1,20})\z/ or die "invalid size for $d in catalog\n";
        $res->{$d} = { size => int($size) };
    }
    return $res;
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

    ($device) = $device =~ m/^([a-z0-9\-]{1,64})\z/ or die "invalid device name\n"; # untaint (perl -T)
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
        # readdir results are tainted under perl -T; the capture untaints them
        my @devs = sort { ($a =~ s/\D//gr) <=> ($b =~ s/\D//gr) } map { m/^(nbd\d+)\z/ ? $1 : () } readdir($dh);
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
        # glob results are tainted under perl -T
        unlink(map { m/^(\Q$dir\E\/[\w.\-]+)\z/ ? $1 : () } glob("$dir/$archive.json $dir/$archive.*.sock"));
    }
    return;
}

# ---------------------------------------------------------------------------
# Container restore (docs/pve-connector.md "Container restore flow"): the
# appliance serves the archive's tar stream over SSH (helper ct-restore-serve)
# on a unix socket in the restore dir: u64 big-endian length, then exactly that
# many bytes of tar. We extract it as root into a staging directory and hand
# that to PVE (mechanism 'directory'), which re-tars it into the new
# container's user namespace.

my $ct_stage_dir = sub {
    my ($self, $volname) = @_;
    # parse_volname's capture untaints (restore runs in a perl -T API worker)
    my (undef, $archive) = $self->plugin()->parse_volname($volname);
    return ($archive, "$STAGEDIR/$archive");
};

sub restore_container_init {
    my ($self, $volname, $storeid, $info) = @_;

    my ($archive, $stage) = $ct_stage_dir->($self, $volname);
    my $a = $self->plugin()->find_archive($self->{storeid}, $volname)
        or die "archive '$volname' not found in NexusBackup catalog\n";
    die "archive '$volname' is not a container backup\n" if $a->{type} ne 'lxc';

    my $gid = PVE::Storage::Custom::NexusBackupPlugin::nexus_group_gid();
    my $dir = $self->restoredir();
    ensure_rendezvous_dir($dir, $gid);
    my $json = "$dir/$archive.json";
    my $sock = "$dir/$archive.ct.sock";
    my $timeout = $self->plugin()->job_timeout($self->{scfg});
    local $SIG{PIPE} = 'IGNORE';

    eval {
        unlink($sock);
        if (!-d $STAGEDIR) {
            mkdir($STAGEDIR, 0700) or die "unable to create $STAGEDIR: $!\n";
        }
        chmod(0700, $STAGEDIR) or die "unable to chmod $STAGEDIR: $!\n";
        $self->restore_container_cleanup($volname, $storeid, {}) if -e $stage;
        mkdir($stage, 0700) or die "unable to create $stage: $!\n";

        my $req = { archive => $archive, type => 'lxc', socket => $sock };
        $write_atomic->($json, JSON->new->utf8->canonical->encode($req) . "\n", $gid);
        $self->_log('info', "container restore requested, waiting for the NexusBackup appliance"
            . " (timeout ${timeout}s)");

        my $deadline = time() + $timeout;
        while (!-S $sock) {
            die "timeout after ${timeout}s waiting for the NexusBackup appliance\n"
                if time() >= $deadline;
            sleep(1);
        }
        my $conn = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock)
            or die "unable to connect to $sock: $!\n";
        binmode($conn);
        unlink($json);

        my $read = sub {
            my ($want) = @_;
            my $buf = '';
            my $sel = IO::Select->new($conn);
            while (length($buf) < $want) {
                die "timeout reading from the NexusBackup appliance\n" if !$sel->can_read($timeout);
                my $n = sysread($conn, $buf, $want - length($buf), length($buf));
                if (!defined($n)) {
                    next if $!{EINTR};
                    die "read from the NexusBackup appliance failed: $!\n";
                }
                die "NexusBackup appliance closed the stream early\n" if $n == 0;
            }
            return $buf;
        };

        my ($hi, $lo) = unpack('NN', $read->(8));
        my $size = $hi * 4294967296 + $lo;
        $self->_log('info', "receiving $size bytes of tar into $stage");

        my $pid = open(my $tar, '|-', 'tar', '--extract', '--file=-', '--numeric-owner',
            '--xattrs', '--xattrs-include=*', '--acls', '--preserve-permissions',
            "--directory=$stage") or die "unable to run tar: $!\n";
        binmode($tar);
        my $left = $size;
        eval {
            while ($left > 0) {
                my $chunk = $read->($left > 1048576 ? 1048576 : $left);
                $left -= length($chunk);
                $write_all->($tar, $chunk, 'tar');
            }
        };
        my $err = $@;
        kill('TERM', $1) if $err && "$pid" =~ m/^(\d+)\z/; # untaint (perl -T)
        close($tar);
        my $status = $?;
        close($conn);
        die $err if $err;
        die "tar extraction failed (exit " . ($status >> 8) . ")\n" if $status != 0;
    };
    if (my $err = $@) {
        eval { $self->restore_container_cleanup($volname, $storeid, {}) };
        die $err;
    }

    return { 'archive-directory' => $stage };
}

sub restore_container_cleanup {
    my ($self, $volname, $storeid, $info) = @_;

    my ($archive, $stage) = $ct_stage_dir->($self, $volname);
    my $dir = $self->restoredir();
    unlink("$dir/$archive.json", "$dir/$archive.ct.sock");
    if (-e $stage) {
        system('rm', '-rf', '--one-file-system', '--', $stage) == 0
            or die "unable to remove $stage (exit " . ($? >> 8) . ")\n";
    }
    return;
}

1;
