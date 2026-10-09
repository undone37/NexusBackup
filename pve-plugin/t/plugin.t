#!/usr/bin/perl -T
# Unit tests for the storage plugin and backup provider against stub PVE base
# classes (t/lib). The real integration test runs on a PVE node (lab).
use strict;
use warnings;

use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use POSIX ();
use Scalar::Util ();
use Socket qw(SOCK_STREAM);
use Test::More;

# Runs under taint mode like PVE's API workers (pvedaemon): catalog data that
# reaches exec/unlink must be untainted by the plugin.
$ENV{PATH} = '/usr/sbin:/usr/bin:/sbin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

use lib dirname(__FILE__) . '/lib';
use lib dirname(__FILE__) . '/..';

use PVE::Storage::Custom::NexusBackupPlugin;

my $P = 'PVE::Storage::Custom::NexusBackupPlugin';
my $tmp = tempdir(CLEANUP => 1);
$PVE::Storage::Custom::NexusBackupPlugin::STATEDIR = "$tmp/state";
$PVE::Storage::Custom::NexusBackupPlugin::RUNDIR = "$tmp/jobs";
$PVE::Storage::Custom::NexusBackupPlugin::RESTOREDIR = "$tmp/restore";
$PVE::Storage::Custom::NexusBackupPlugin::GROUP = scalar(getgrgid($)));
mkdir("$tmp/jobs") or die;

my $scfg = { type => 'nexusbackup', content => { backup => 1 } };
my @warnings;
$SIG{__WARN__} = sub { push @warnings, @_ };

is($P->api(), 11, 'api 11');
is($P->type(), 'nexusbackup', 'type');
ok($P->plugindata()->{features}->{'backup-provider'}, 'backup-provider feature');
ok(exists $P->options()->{'nexus-fleecing-storage'}, 'fleecing option');
ok($P->options()->{'nexus-job-timeout'}->{optional}, 'job timeout optional');

is_deeply([$P->parse_volname('backup/nexus-100-1760000000')],
    ['backup', 'nexus-100-1760000000', '100', undef, undef, undef, 'nexus'], 'parse_volname');
ok(!eval { $P->parse_volname('backup/vzdump-qemu-100.vma'); 1 }, 'parse_volname rejects foreign');

# missing index
ok($P->activate_storage('nexus', $scfg), 'activate_storage');
ok(-d "$tmp/state/nexus", 'activate_storage creates state dir');
ok($P->check_connection('nexus', $scfg), 'check_connection');
is_deeply($P->list_volumes('nexus', $scfg, undef, ['backup']), [], 'list empty without index');
is_deeply([$P->status('nexus', $scfg)], [0, 0, 0, 1], 'status without index');
is_deeply($P->prune_backups($scfg, 'nexus', {}, 100, 'qemu', 0, undef), [], 'prune empty');

sub put_index {
    my ($raw) = @_;
    my $f = "$tmp/state/nexus/index.json";
    open(my $fh, '>', "$f.new") or die;
    print {$fh} $raw;
    close($fh);
    rename("$f.new", $f) or die;
    utime(time, time + int(rand(1000)), $f); # defeat the mtime cache within one second
}

put_index('{ not json');
is_deeply($P->list_volumes('nexus', $scfg, undef, ['backup']), [], 'list empty on broken index');

put_index(JSON->new->encode({
    version => 1, total => 1000, used => 400,
    archives => [
        { volname => 'backup/nexus-100-1760000000', vmid => 100, ctime => 1760000000,
          size => 4096, devices => ['drive-scsi0'], config => "memory: 1024\n",
          firewall => undef, notes => 'n1', protected => JSON::true },
        { volname => 'backup/nexus-101-1760000100', vmid => 101, ctime => 1760000100,
          size => 8192, devices => ['drive-scsi0', 'drive-efidisk0'], config => "cores: 2\n",
          device_sizes => { 'drive-scsi0' => 6144, 'drive-efidisk0' => 2048, '../bad' => 1 },
          firewall => "[OPTIONS]\nenable: 1\n", notes => '', protected => JSON::false },
        { volname => '../../etc/passwd', vmid => 1 },
        { volname => 'backup/nexus-102-1', vmid => 999 },
        'garbage',
    ],
}));

my $all = $P->list_volumes('nexus', $scfg, undef, ['backup']);
is(scalar(@$all), 2, 'list: invalid entries skipped');
is_deeply($all->[0], {
    volid => 'nexus:backup/nexus-100-1760000000', vmid => 100, format => 'nexus',
    ctime => 1760000000, size => 4096, subtype => 'qemu', content => 'backup',
    notes => 'n1', protected => 1,
}, 'list entry');
is(scalar(@{ $P->list_volumes('nexus', $scfg, 101, ['backup']) }), 1, 'list by vmid');
is_deeply($P->list_volumes('nexus', $scfg, undef, ['images']), [], 'list other content');
is_deeply([$P->status('nexus', $scfg)], [1000, 600, 400, 1], 'status from index');
is(scalar($P->volume_size_info($scfg, 'nexus', 'backup/nexus-101-1760000100')), 8192, 'size');
is($P->get_volume_attribute($scfg, 'nexus', 'backup/nexus-100-1760000000', 'notes'), 'n1', 'notes');
is($P->get_volume_attribute($scfg, 'nexus', 'backup/nexus-100-1760000000', 'protected'), 1,
    'protected');

my $pr = $P->prune_backups($scfg, 'nexus', { 'keep-last' => 1 }, 100, 'qemu', 0, undef);
is_deeply([map { $_->{mark} } @$pr], ['keep'], 'prune marks keep');
is_deeply($P->prune_backups($scfg, 'nexus', {}, undef, 'lxc', 0, undef), [], 'prune lxc empty');

like((eval { $P->free_image('nexus', $scfg, 'backup/nexus-100-1760000000') } // $@),
    qr/deletion is managed by the NexusBackup appliance/, 'free_image dies');
like((eval { $P->update_volume_attribute($scfg, 'nexus', 'backup/nexus-100-1760000000',
    'protected', 0) } // $@), qr/deletion is managed by the NexusBackup appliance/,
    'update_volume_attribute dies');

# --- backup provider -----------------------------------------------------------
my @log;
my $prov = $P->new_backup_provider({ %$scfg, 'nexus-job-timeout' => 3 }, 'nexus',
    sub { push @log, [@_] });
isa_ok($prov, 'PVE::BackupProvider::Plugin::NexusBackup');
is($prov->provider_name(), 'NexusBackup', 'provider_name');
ok(!defined($prov->job_init(1760000000)), 'job_init');
is_deeply($prov->backup_init(101, 'qemu', 1760000200), { 'archive-name' => 'nexus-101-1760000200' },
    'backup_init');
is($prov->backup_get_mechanism(101, 'qemu'), 'nbd', 'mechanism qemu');
is($prov->backup_get_mechanism(101, 'lxc'), 'directory', 'mechanism lxc');
like((eval { $prov->backup_get_mechanism(101, 'foo') } // $@), qr/unsupported guest type/,
    'mechanism unknown type dies');
is_deeply($prov->backup_vm_query_incremental(101, { 'drive-scsi0' => { size => 1 },
    'drive-scsi1' => { size => 1 } }), { 'drive-scsi0' => 'use', 'drive-scsi1' => 'new' },
    'query_incremental');
is_deeply($prov->backup_vm_query_incremental(555, { 'drive-scsi0' => { size => 1 } }),
    { 'drive-scsi0' => 'new' }, 'query_incremental unknown vm');
is($prov->archive_get_guest_config('backup/nexus-101-1760000100', 'nexus'), "cores: 2\n",
    'guest config');
is($prov->archive_get_firewall_config('backup/nexus-101-1760000100', 'nexus'),
    "[OPTIONS]\nenable: 1\n", 'firewall config');
ok(!defined($prov->archive_get_firewall_config('backup/nexus-100-1760000000', 'nexus')),
    'no firewall config');
ok(!eval { $prov->archive_get_guest_config('backup/nexus-1-1', 'nexus'); 1 }, 'unknown archive');
is_deeply([$prov->restore_get_mechanism('backup/nexus-101-1760000100')], ['qemu-img', 'qemu'],
    'restore mechanism');
is_deeply($prov->restore_vm_init('backup/nexus-101-1760000100'),
    { 'drive-scsi0' => { size => 6144 }, 'drive-efidisk0' => { size => 2048 } }, 'restore_vm_init');
like((eval { $prov->restore_vm_init('backup/nexus-100-1760000000') } // $@),
    qr/no device sizes/, 'restore_vm_init without device_sizes');
ok(eval { system('true', map { $_->{size} } values %{ $prov->restore_vm_init('backup/nexus-101-1760000100') }) == 0 },
    'restore_vm_init sizes are untainted (usable in exec)') or diag($@);
{
    # nobody serves the device: request published, then timeout and cleanup
    my $t0 = time();
    my $seen;
    my $watch = fork() // die;
    if (!$watch) {
        for (1 .. 60) {
            POSIX::_exit(0) if -e "$tmp/restore/nexus-101-1760000100.json";
            select(undef, undef, undef, 0.05);
        }
        POSIX::_exit(1);
    }
    like((eval { $prov->restore_vm_volume_init('backup/nexus-101-1760000100', 'drive-scsi0', {}) }
        // $@), qr/timeout after 3s/, 'restore_vm_volume_init times out');
    waitpid($watch, 0);
    is($? >> 8, 0, 'restore request was published');
    ok(!-e "$tmp/restore/nexus-101-1760000100.json", 'restore request removed');
    ok(!eval { $prov->restore_vm_volume_init('backup/nexus-101-1760000100', '../x', {}); 1 },
        'invalid device rejected');
    ok(eval { $prov->restore_vm_cleanup('backup/nexus-101-1760000100'); 1 }, 'restore_vm_cleanup');
}

my $qdir = "$tmp/qemu/101.backup-access.$$";
system('mkdir', '-p', $qdir) == 0 or die;
chmod(0700, $qdir);
my $sock = "$qdir/101-nbd.backup-access";
my $listen = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $sock, Listen => 128) or die $!;
chmod(0700, $sock);
my $volumes = {
    'drive-scsi0' => { size => 1024, 'bitmap-mode' => 'reuse', 'nbd-path' => "$qdir//101-nbd.backup-access",
        'bitmap-name' => 'snapshot-access:nexus' },
    'drive-efidisk0' => { size => 512, 'bitmap-mode' => 'none', 'nbd-path' => "$qdir//101-nbd.backup-access" },
};
my $jobs = "$tmp/jobs";

# Fake appliance: waits for the job, checks it, writes the done file.
sub appliance {
    my ($result) = @_;
    my $pid = fork() // die;
    return $pid if $pid;
    for (1 .. 100) {
        last if -e "$jobs/101.json";
        select(undef, undef, undef, 0.05);
    }
    my $raw = do { local (@ARGV, $/) = ("$jobs/101.json"); <> } // POSIX::_exit(2);
    my $job = JSON->new->decode($raw);
    POSIX::_exit(3) if $job->{nbd_socket} ne "$jobs/101.nbd" || !-S $job->{nbd_socket};
    POSIX::_exit(4) if $job->{devices}->[0]->{name} ne 'drive-efidisk0';
    POSIX::_exit(5) if ((stat("$jobs/101.json"))[2] & 07777) != 0640;
    my ($peer) = $job->{nbd_socket} =~ m/^(.*)\z/s; # fake appliance (the real helper is not -T)
    POSIX::_exit(6) if !IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $peer);
    if (defined($result)) {
        open(my $fh, '>', "$jobs/.101.tmp") or POSIX::_exit(7);
        print {$fh} "$result\n";
        close($fh);
        rename("$jobs/.101.tmp", "$jobs/101.done");
    }
    POSIX::_exit(0);
}

my $app = appliance('ok');
ok(eval { $prov->backup_vm(101, "cores: 2\n", $volumes, { 'firewall-config' => "x\n" }); 1 },
    'backup_vm ok') or diag($@);
waitpid($app, 0);
is($? >> 8, 0, 'fake appliance validated the job');
ok(!-e "$jobs/101.json" && !-e "$jobs/101.done" && !-e "$jobs/101.nbd", 'files cleaned up (ok)');
ok(-S $sock, 'original socket untouched');
is((stat($sock))[2] & 0060, 0060, 'socket group rw');
is_deeply($prov->backup_cleanup(101, 'qemu', 1, {}), { stats => { 'archive-size' => 1536 } },
    'backup_cleanup size');
@log = ();
$prov->backup_cleanup(101, 'qemu', 0, { error => 'prune failed' });
ok((grep { $_->[0] eq 'warn' && $_->[1] =~ /snapshot is kept/ } @log), 'late failure keeps snapshot');

$app = appliance('fail disk read error');
like((eval { $prov->backup_vm(101, "cores: 2\n", $volumes, {}) } // $@),
    qr/appliance reported failure: disk read error/, 'backup_vm fail');
waitpid($app, 0);
ok(!-e "$jobs/101.json" && !-e "$jobs/101.done" && !-e "$jobs/101.nbd", 'files cleaned up (fail)');

$app = appliance(undef);
like((eval { $prov->backup_vm(101, "cores: 2\n", $volumes, {}) } // $@), qr/timeout after 3s/,
    'backup_vm timeout');
waitpid($app, 0);
ok(!-e "$jobs/101.json" && !-e "$jobs/101.nbd", 'files cleaned up (timeout)');

{
    # task abort: vzdump turns SIGTERM into a die inside backup_vm
    local $SIG{TERM} = sub { die "interrupted by signal\n" };
    my $parent = $$;
    my $killer = fork() // die;
    if (!$killer) { sleep(1); kill('TERM', $parent); POSIX::_exit(0) }
    like((eval { $prov->backup_vm(101, "cores: 2\n", $volumes, {}) } // $@),
        qr/interrupted by signal/, 'backup_vm abort');
    waitpid($killer, 0);
    ok(!-e "$jobs/101.json" && !-e "$jobs/101.nbd", 'files cleaned up (abort)');
}

# stale done file from an older job must not complete a new one
open(my $fh, '>', "$jobs/101.done") or die;
print {$fh} "ok\n";
close($fh);
$app = appliance('fail second');
like((eval { $prov->backup_vm(101, "cores: 2\n", $volumes, {}) } // $@), qr/fail.*second/,
    'stale done file ignored');
waitpid($app, 0);

my $logf = "$tmp/task.log";
open($fh, '>', $logf) or die;
print {$fh} "INFO: hello\n";
close($fh);
$prov->backup_handle_log_file(101, $logf);
is(do { local (@ARGV, $/) = ("$tmp/state/nexus/logs/nexus-101-1760000200.log"); <> },
    "INFO: hello\n", 'task log copied');

# --- containers --------------------------------------------------------------
# Inputs from vzdump/PVE are tainted in API workers; make ours tainted too.
my $TAINTED = do { open(my $fh, '<', __FILE__) or die; my $l = <$fh>; close($fh); substr($l, 0, 0) };
sub taint { return $_[0] . $TAINTED }
ok(Scalar::Util::tainted(taint('x')), 'test inputs are tainted');

put_index(JSON->new->encode({
    version => 1,
    archives => [
        { volname => 'backup/nexus-101-1760000100', vmid => 101, ctime => 1760000100,
          devices => ['drive-scsi0'], device_sizes => { 'drive-scsi0' => 6144 }, config => "cores: 2\n" },
        { volname => 'backup/nexus-200-1760000300', vmid => 200, type => 'lxc', ctime => 1760000300,
          size => 10240, devices => [], config => "arch: amd64\nunprivileged: 1\n", firewall => undef },
        { volname => 'backup/nexus-201-1760000400', vmid => 201, type => 'bogus', ctime => 1760000400 },
    ],
}));
my %sub = map { $_->{vmid} => $_->{subtype} } $P->list_volumes('nexus', $scfg, undef, ['backup'])->@*;
is_deeply(\%sub, { 101 => 'qemu', 200 => 'lxc', 201 => 'qemu' }, 'list: subtype from catalog type');
is_deeply([map { "$_->{vmid}:$_->{type}" } $P->prune_backups($scfg, 'nexus', {}, undef, 'lxc', 0, undef)->@*],
    ['200:lxc'], 'prune lxc lists containers only');
is(scalar(grep { $_->{vmid} == 200 } $P->prune_backups($scfg, 'nexus', {}, undef, 'qemu', 0, undef)->@*), 0,
    'prune qemu skips containers');
is(scalar($P->volume_size_info($scfg, 'nexus', 'backup/nexus-200-1760000300')), 10240, 'ct size');
is($prov->archive_get_guest_config('backup/nexus-200-1760000300', 'nexus'), "arch: amd64\nunprivileged: 1\n",
    'ct guest config');
is_deeply([$prov->restore_get_mechanism('backup/nexus-200-1760000300', 'nexus')], ['directory', 'lxc'],
    'restore mechanism lxc');
is_deeply([$prov->restore_get_mechanism('backup/nexus-101-1760000100', 'nexus')], ['qemu-img', 'qemu'],
    'restore mechanism qemu');
is_deeply($prov->backup_vm_query_incremental(200, { 'drive-scsi0' => { size => 1 } }),
    { 'drive-scsi0' => 'new' }, 'query_incremental ignores container archives');

# tar command line
{
    my $cmd = PVE::BackupProvider::Plugin::NexusBackup::ct_tar_command(
        { directory => taint('/mnt/vzsnap0'), sources => [taint('.'), taint('./data')],
          'backup-user-id' => 100000 },
        [taint('/tmp/?*'), taint('*.cache'), taint('/var/run/?*.pid')]);
    is_deeply($cmd, ['tar', '--create', '--file=-', '--numeric-owner', '--xattrs', '--xattrs-include=*',
        '--acls', '--sparse', '--one-file-system', '--preserve-permissions', '--warning=no-file-ignored',
        '--directory=/mnt/vzsnap0', '--no-anchored', '--exclude=lost+found', '--exclude=*.cache',
        '--anchored', '--exclude=./tmp/?*', '--exclude=./var/run/?*.pid', '--', '.', './data'],
        'tar command (unprivileged, excludes, mount point source)');
    ok(!grep({ Scalar::Util::tainted($_) } @$cmd), 'tar command is untainted');
    my $priv = PVE::BackupProvider::Plugin::NexusBackup::ct_tar_command(
        { directory => '/x', 'backup-user-id' => 0 }, []);
    ok(!grep({ $_ eq '--exclude=lost+found' } @$priv), 'privileged: lost+found kept');
    is($priv->[-1], '.', 'default source .');
    for my $bad ({ directory => 'rel' }, { directory => "/x\n" }, { directory => '/x', sources => ['/etc'] },
        { directory => '/x', sources => ['../x'] }) {
        ok(!eval { PVE::BackupProvider::Plugin::NexusBackup::ct_tar_command($bad, []); 1 },
            'invalid tar input rejected');
    }
    ok(!eval { PVE::BackupProvider::Plugin::NexusBackup::ct_tar_command({ directory => '/x' }, ["a\nb"]); 1 },
        'invalid exclude pattern rejected');
}

# a small container root
my $ctroot = "$tmp/ctroot";
system('mkdir', '-p', "$ctroot/etc", "$ctroot/tmp", "$ctroot/home/u", "$ctroot/lost+found") == 0 or die;
my %files = ("etc/shadow" => "root:*:1::::::\n", "home/u/marker" => "marker " . rand() . "\n",
    "tmp/junk" => "x", "home/u/skip.me" => "y");
for my $f (keys %files) {
    open(my $fh, '>', "$ctroot/$f") or die;
    print {$fh} $files{$f};
    close($fh);
}
chmod(0640, "$ctroot/etc/shadow");
chmod(0751, "$ctroot/home/u");
symlink('marker', "$ctroot/home/u/link") or die;

my $ct_info = sub {
    return { directory => taint($_[0] // $ctroot), sources => [taint('.')], 'backup-user-id' => 100000,
        'firewall-config' => "[OPTIONS]\nenable: 1\n" };
};

# Fake appliance for ct-stream: reads the records, stores the tar, answers $answer.
sub ct_appliance {
    my ($answer) = @_;
    my $pid = fork() // die;
    return $pid if $pid;
    for (1 .. 100) {
        last if -e "$jobs/200.json";
        select(undef, undef, undef, 0.05);
    }
    my $job = eval { JSON->new->decode(do { local (@ARGV, $/) = ("$jobs/200.json"); <> }) } // POSIX::_exit(2);
    POSIX::_exit(3) if $job->{type} ne 'lxc' || $job->{archive} ne 'nexus-200-1760000300'
        || $job->{socket} ne "$jobs/200.ct.sock" || $job->{firewall} ne "[OPTIONS]\nenable: 1\n";
    POSIX::_exit(4) if ((stat("$jobs/200.ct.sock"))[2] & 0777) != 0660;
    my $c = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => "$jobs/200.ct.sock") or POSIX::_exit(5);
    binmode($c);
    my $read = sub {
        my ($n) = @_;
        my $buf = '';
        while (length($buf) < $n) {
            my $r = sysread($c, $buf, $n - length($buf), length($buf));
            POSIX::_exit(6) if !$r;
        }
        return $buf;
    };
    my ($tar, $cfg, $end) = ('', undef, undef);
    while (!defined($end)) {
        my ($tag, $len) = unpack('aN', $read->(5));
        my $data = $len ? $read->($len) : '';
        if ($tag eq 'C') { $cfg = $data }
        elsif ($tag eq 'D') { $tar .= $data }
        elsif ($tag eq 'E') { $end = $data }
        else { POSIX::_exit(7) }
    }
    open(my $out, '>', "$tmp/got.tar") or POSIX::_exit(8);
    print {$out} $tar;
    close($out);
    open($out, '>', "$tmp/got.end") or POSIX::_exit(8);
    print {$out} "$end\n" . ($cfg // '');
    close($out);
    syswrite($c, $answer) if defined($answer);
    shutdown($c, 1);
    my $rest;
    1 while sysread($c, $rest, 4096); # node closes after reading the answer
    POSIX::_exit(0);
}

# backup_container runs in a forked child (PVE: run_in_userns -> run_fork)
sub run_ct_backup {
    my ($info, $excl) = @_;
    my $pid = fork() // die;
    if (!$pid) {
        eval { $prov->backup_container(200, "arch: amd64\n", $excl, $info) };
        if (my $err = $@) {
            open(my $fh, '>', "$tmp/ct.err");
            print {$fh} $err;
            close($fh);
            POSIX::_exit(1);
        }
        POSIX::_exit(0);
    }
    waitpid($pid, 0);
    my $rc = $? >> 8;
    my $err = $rc ? do { local (@ARGV, $/) = ("$tmp/ct.err"); <> } : undef;
    return ($rc, $err);
}

is_deeply($prov->backup_init(200, 'lxc', 1760000300), { 'archive-name' => 'nexus-200-1760000300' },
    'backup_init lxc');
{
    my $app = ct_appliance("ok\n");
    ok(eval { $prov->backup_container_prepare(200, $ct_info->()); 1 }, 'backup_container_prepare') or diag($@);
    my ($rc, $err) = run_ct_backup($ct_info->(), [taint('/tmp/?*'), taint('skip.me')]);
    is($rc, 0, 'backup_container ok') or diag($err);
    waitpid($app, 0);
    is($? >> 8, 0, 'fake appliance got a valid job, stream and status');
    my $stats = $prov->backup_cleanup(200, 'lxc', 1, {});
    is($stats->{stats}->{'archive-size'}, -s "$tmp/got.tar", 'archive-size = stream length');
    ok(!-e "$jobs/200.json" && !-e "$jobs/200.ct.sock", 'job file and socket removed');
    is(do { local (@ARGV, $/) = ("$tmp/got.end"); <> }, "ok\narch: amd64\n", 'status ok, config record');

    my %list;
    open(my $tl, '-|', 'tar', '--list', '--verbose', '--numeric-owner', '--file', "$tmp/got.tar") or die;
    while (<$tl>) {
        my ($mode, $path) = m/^(\S+)\s.*\s(\.\/\S*?)(?: -> \S+)?$/ or next;
        $list{$path} = $mode;
    }
    close($tl);
    is($list{'./etc/shadow'}, '-rw-r-----', 'shadow mode in stream');
    is($list{'./home/u/'}, 'drwxr-x--x', 'dir mode in stream');
    ok(exists $list{'./home/u/marker'} && exists $list{'./home/u/link'}, 'file and symlink in stream');
    ok(!exists $list{'./tmp/junk'}, 'anchored exclude applied');
    ok(exists $list{'./tmp/'}, 'excluded dir itself kept');
    ok(!exists $list{'./home/u/skip.me'}, 'floating exclude applied');
    ok(!grep({ m/lost\+found/ } keys %list), 'lost+found excluded (unprivileged)');
}
{
    my $app = ct_appliance("fail store full\n");
    $prov->backup_container_prepare(200, $ct_info->());
    my ($rc, $err) = run_ct_backup($ct_info->(), []);
    like($err // '', qr/appliance reported failure: store full/, 'appliance failure propagates');
    waitpid($app, 0);
    @log = ();
    is_deeply($prov->backup_cleanup(200, 'lxc', 0, { error => $err }), {}, 'cleanup after failure');
    ok(!(grep { $_->[1] =~ /snapshot is kept/ } @log), 'no committed snapshot claimed');
    ok(!-e "$jobs/200.json" && !-e "$jobs/200.ct.sock", 'job files removed (fail)');
}
{
    my $app = ct_appliance(undef); # closes without answering
    $prov->backup_container_prepare(200, $ct_info->());
    my ($rc, $err) = run_ct_backup($ct_info->("$tmp/does-not-exist"), []);
    like($err // '', qr/tar failed/, 'tar failure dies');
    waitpid($app, 0);
    like(do { local (@ARGV, $/) = ("$tmp/got.end"); <> }, qr/^fail tar failed/, 'appliance sees E fail');
    $prov->backup_cleanup(200, 'lxc', 0, {});
}
{
    $prov->backup_container_prepare(200, $ct_info->());
    my $t0 = time();
    my ($rc, $err) = run_ct_backup($ct_info->(), []);
    like($err // '', qr/timeout waiting for the NexusBackup appliance/, 'no appliance: timeout');
    ok(time() - $t0 <= 6, 'timeout honours nexus-job-timeout');
    $prov->backup_cleanup(200, 'lxc', 0, {});
    ok(!-e "$jobs/200.json" && !-e "$jobs/200.ct.sock", 'job files removed (timeout)');
}

# --- container restore ---------------------------------------------------------
$PVE::BackupProvider::Plugin::NexusBackup::STAGEDIR = "$tmp/stage";
my $rarch = 'nexus-200-1760000300';
my $tarbytes = do { local (@ARGV, $/) = ("$tmp/got.tar"); <> };
# the failure case above overwrote got.tar; recreate a full stream
{
    my $app = ct_appliance("ok\n");
    $prov->backup_container_prepare(200, $ct_info->());
    run_ct_backup($ct_info->(), [taint('/tmp/?*')]);
    waitpid($app, 0);
    $prov->backup_cleanup(200, 'lxc', 1, {});
    $tarbytes = do { local (@ARGV, $/) = ("$tmp/got.tar"); <> };
}

# Fake ct-restore-serve: waits for the request, listens, sends length + $data.
sub ct_serve {
    my ($len, $data) = @_;
    my $pid = fork() // die;
    return $pid if $pid;
    for (1 .. 100) {
        last if -e "$tmp/restore/$rarch.json";
        select(undef, undef, undef, 0.05);
    }
    my $req = eval { JSON->new->decode(do { local (@ARGV, $/) = ("$tmp/restore/$rarch.json"); <> }) }
        // POSIX::_exit(2);
    POSIX::_exit(3) if $req->{type} ne 'lxc' || $req->{archive} ne $rarch;
    my $l = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => "$tmp/restore/.x.sock", Listen => 1)
        or POSIX::_exit(4);
    rename("$tmp/restore/.x.sock", "$tmp/restore/$rarch.ct.sock") or POSIX::_exit(5);
    my $c = $l->accept() or POSIX::_exit(6);
    binmode($c);
    my $buf = pack('NN', int($len / 4294967296), $len % 4294967296) . $data;
    my $off = 0;
    while ($off < length($buf)) {
        my $w = syswrite($c, $buf, length($buf) - $off, $off);
        last if !$w;
        $off += $w;
    }
    close($c);
    POSIX::_exit(0);
}

ok(!eval { $prov->restore_container_init('backup/nexus-101-1760000100', 'nexus', {}); 1 },
    'restore_container_init refuses VM archives');
{
    my $srv = ct_serve(length($tarbytes), $tarbytes);
    my $res = eval { $prov->restore_container_init("backup/$rarch", 'nexus', {}) };
    is_deeply($res, { 'archive-directory' => "$tmp/stage/$rarch" }, 'restore_container_init') or diag($@);
    waitpid($srv, 0);
    is($? >> 8, 0, 'fake ct-restore-serve ok');
    my $d = "$tmp/stage/$rarch";
    is((stat($d))[2] & 07777, (stat($ctroot))[2] & 07777, 'staging dir gets the archived root mode');
    is((stat("$tmp/stage"))[2] & 07777, 0700, 'staging root 0700');
    is(do { local (@ARGV, $/) = ("$d/home/u/marker"); <> }, $files{'home/u/marker'}, 'marker restored');
    is((stat("$d/etc/shadow"))[2] & 07777, 0640, 'shadow mode restored');
    is((stat("$d/home/u"))[2] & 07777, 0751, 'dir mode restored');
    is(readlink("$d/home/u/link"), 'marker', 'symlink restored');
    ok(!-e "$d/tmp/junk", 'excluded file absent');
    ok(!-e "$tmp/restore/$rarch.json", 'request removed');
    ok(eval { $prov->restore_container_cleanup("backup/$rarch", 'nexus', {}); 1 }, 'cleanup') or diag($@);
    ok(!-e $d, 'staging dir removed');
}
{
    my $srv = ct_serve(length($tarbytes) + 100, $tarbytes); # truncated stream
    like((eval { $prov->restore_container_init("backup/$rarch", 'nexus', {}) } // $@),
        qr/closed the stream early/, 'truncated restore stream dies');
    waitpid($srv, 0);
    ok(!-e "$tmp/stage/$rarch" && !-e "$tmp/restore/$rarch.json", 'cleaned up after truncation');
}
{
    my $srv = ct_serve(1024, "\x01" x 1024); # not a tar
    like((eval { $prov->restore_container_init("backup/$rarch", 'nexus', {}) } // $@),
        qr/tar extraction failed/, 'garbage stream dies');
    waitpid($srv, 0);
    ok(!-e "$tmp/stage/$rarch", 'cleaned up after tar failure');
}
{
    like((eval { $prov->restore_container_init("backup/$rarch", 'nexus', {}) } // $@),
        qr/timeout after 3s/, 'restore without appliance times out');
    ok(!-e "$tmp/stage/$rarch" && !-e "$tmp/restore/$rarch.json", 'cleaned up after timeout');
}

# --- instant recovery overlays ------------------------------------------------
$PVE::Storage::Custom::NexusBackupPlugin::IRDIR = "$tmp/ir";
$PVE::Storage::Custom::NexusBackupPlugin::IRRUNDIR = '/run/nexusbackup/ir';
{
    my $vol = 'ir/903/nexus-101-1760000100.drive-scsi0.qcow2';
    my $volid = "nexus:$vol";
    my $overlay = "$tmp/ir/nexus/903/nexus-101-1760000100.drive-scsi0.qcow2";
    ok($P->plugindata()->{content}->[0]->{images}, 'images content offered');
    is_deeply([$P->parse_volname($vol)],
        ['images', 'nexus-101-1760000100.drive-scsi0.qcow2', '903', undef, undef, 0, 'qcow2'],
        'parse_volname ir');
    for my $bad ('ir/903/../x.qcow2', 'ir/abc/nexus-101-1760000100.drive-scsi0.qcow2',
        'ir/903/nexus-101-1760000100.drive-scsi0', 'ir/903/nexus-101-1760000100.Drive.qcow2',
        'ir/903/sub/nexus-101-1760000100.drive-scsi0.qcow2', "$vol\n") {
        ok(!eval { $P->parse_volname($bad); 1 }, "parse_volname rejects '$bad'");
    }
    is_deeply([$P->path($scfg, $vol, 'nexus')], [$overlay, '903', 'images'], 'path of ir volume');
    my $isize = $P->volume_size_info($scfg, taint('nexus'), taint($vol));
    is($isize, 6144, 'ir size from catalog');
    ok(!Scalar::Util::tainted($isize), 'ir size untainted (PVE passes it to lvcreate)');
    is_deeply($P->list_images('nexus', $scfg, 903), [], 'no overlay before activation');

    ok(eval { $P->activate_volume(taint('nexus'), $scfg, taint($vol)); 1 }, 'activate creates overlay')
        or diag($@);
    ok(-f $overlay, 'overlay exists');
    is((stat("$tmp/ir/nexus/903"))[2] & 0777, 0700, 'overlay dir private');
    my $info = JSON->new->decode(scalar(`qemu-img info --output=json $overlay`));
    is($info->{format}, 'qcow2', 'overlay format');
    is($info->{'virtual-size'}, 6144, 'overlay size');
    is($info->{'backing-filename-format'}, 'raw', 'backing format raw');
    is($info->{'backing-filename'},
        'json:{"driver":"raw","file":{"driver":"nbd","export":"drive-scsi0","open-timeout":60,'
        . '"reconnect-delay":60,"server":{"path":"/run/nexusbackup/ir/903.nexus-101-1760000100.drive-scsi0.sock",'
        . '"type":"unix"}}}', 'backing = helper socket of this vmid/archive/device');
    my $mtime = (stat($overlay))[9];
    utime(1, 1, $overlay);
    ok(eval { $P->activate_volume('nexus', $scfg, $vol); 1 }, 're-activate');
    is((stat($overlay))[9], 1, 'existing overlay (guest writes) kept');
    ok(!grep({ /\.tmp$/ } glob("$tmp/ir/nexus/903/.*")), 'no temp files left');

    my $l = $P->list_images('nexus', $scfg, 903);
    is(scalar(@$l), 1, 'list_images: one overlay');
    is_deeply([@{ $l->[0] }{qw(volid format vmid size)}], [$volid, 'qcow2', 903, 6144], 'list_images entry');
    is_deeply($P->list_images('nexus', $scfg, 904), [], 'list_images filters by vmid');
    is_deeply($P->list_images('nexus', $scfg, undef, ['nexus:other']), [], 'list_images filters by vollist');
    is_deeply([map { "$_->{content}:$_->{volid}" } $P->list_volumes('nexus', $scfg, 903, ['images'])->@*],
        ["images:$volid"], 'list_volumes images');
    ok(!grep({ $_->{content} eq 'images' } $P->list_volumes('nexus', $scfg, undef, ['backup'])->@*),
        'list_volumes backup only');
    is_deeply($P->list_images('other', $scfg, 903), [], 'overlays are per storage');

    like((eval { $P->activate_volume('nexus', $scfg, 'ir/903/nexus-101-1760000100.drive-efidisk0.qcow2') } // $@),
        qr/has no device/, 'unknown device refused');
    like((eval { $P->activate_volume('nexus', $scfg, 'ir/903/nexus-200-1760000300.drive-scsi0.qcow2') } // $@),
        qr/not a VM backup/, 'container archive refused');
    like((eval { $P->activate_volume('nexus', $scfg, 'ir/903/nexus-101-1.drive-scsi0.qcow2') } // $@),
        qr/not found in NexusBackup catalog/, 'unknown archive refused');

    my $link = "$tmp/ir/nexus/903/nexus-101-1760000100.drive-sata0.qcow2";
    symlink('/etc/passwd', $link) or die;
    like((eval { $P->activate_volume('nexus', $scfg, 'ir/903/nexus-101-1760000100.drive-sata0.qcow2') } // $@),
        qr/not a regular file/, 'symlinked overlay refused');
    unlink($link);
    chmod(0770, "$tmp/ir/nexus/903");
    like((eval { $P->activate_volume('nexus', $scfg, $vol) } // $@),
        qr/without group\/other write access/, 'group-writable overlay dir refused');
    chmod(0700, "$tmp/ir/nexus/903");

    like((eval { $P->free_image('nexus', $scfg, 'backup/nexus-101-1760000100') } // $@),
        qr/deletion is managed by the NexusBackup appliance/, 'backups stay undeletable');
    ok(eval { $P->free_image(taint('nexus'), $scfg, taint($vol)); 1 }, 'free_image ir') or diag($@);
    ok(!-e $overlay && !-e "$tmp/ir/nexus/903", 'overlay and empty vmid dir removed');
    ok(eval { $P->free_image('nexus', $scfg, $vol); 1 }, 'free_image of a missing overlay is fine');
    like((eval { $P->alloc_image('nexus', $scfg, 903, 'qcow2', undef, 1024) } // $@),
        qr/cannot hold disk images/, 'alloc_image still refused');
}

# --- security review regressions (docs/security-review.md) -------------------
{
    # task log: root must not write through a logs dir the helper swapped in
    my $state = "$tmp/state/nexus";
    ok((lstat($state))[2] & 01000, 'state dir is sticky');
    $prov->{archive}->{101} = 'nexus-101-1760000999';
    rename("$state/logs", "$state/logs.root") or die;
    mkdir("$tmp/evil") or die;
    symlink("$tmp/evil", "$state/logs") or die;
    $prov->backup_handle_log_file(101, $logf);
    ok(!-e "$tmp/evil/nexus-101-1760000999.log" && !-e "$tmp/evil/nexus-101-1760000999.log.tmp",
        'no task log written through a symlinked logs dir');
    unlink("$state/logs");
    mkdir("$state/logs", 0770) or die;
    chmod(0770, "$state/logs");
    $prov->backup_handle_log_file(101, $logf);
    ok(!-e "$state/logs/nexus-101-1760000999.log", 'no task log into a group-writable logs dir');
    rmdir("$state/logs");
    rename("$state/logs.root", "$state/logs") or die;
    symlink("/etc/passwd", "$state/logs/nexus-101-1760000999.log.tmp") or die;
    $prov->backup_handle_log_file(101, $logf);
    is(do { local (@ARGV, $/) = ("$state/logs/nexus-101-1760000999.log"); <> }, "INFO: hello\n",
        'planted tmp symlink replaced, not followed');

    # guest config from the catalog: root-only keys are dropped
    put_index(JSON->new->encode({ version => 1, archives => [
        { volname => 'backup/nexus-300-1760000500', vmid => 300, type => 'lxc', ctime => 1760000500, size => 1,
          config => "arch: amd64\nlxc.hook.pre-start: /bin/sh -c id\nLXC.cgroup2.devices.allow = a\n"
              . "hookscript: local:snippets/x.pl\n[snap]\nargs: -chardev x\ncores: 2\n" },
    ]}));
    is($prov->archive_get_guest_config('backup/nexus-300-1760000500', 'nexus'),
        "arch: amd64\n[snap]\ncores: 2\n", 'root-only config keys dropped');

    # staging dir: a pre-created symlink in the world-writable parent is refused
    File::Path::remove_tree($PVE::BackupProvider::Plugin::NexusBackup::STAGEDIR);
    symlink("$tmp/evil", $PVE::BackupProvider::Plugin::NexusBackup::STAGEDIR) or die;
    like((eval { $prov->restore_container_init('backup/nexus-300-1760000500', 'nexus', {}); 1 } // $@),
        qr/must be a directory owned/, 'symlinked staging dir refused');
}

done_testing();
