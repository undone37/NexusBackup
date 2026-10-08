#!/usr/bin/perl
# Unit tests for the storage plugin and backup provider against stub PVE base
# classes (t/lib). The real integration test runs on a PVE node (lab).
use strict;
use warnings;

use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use POSIX ();
use Socket qw(SOCK_STREAM);
use Test::More;

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
like((eval { $prov->backup_get_mechanism(101, 'lxc') } // $@), qr/not supported in v1/,
    'mechanism lxc dies');
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
    POSIX::_exit(6) if !IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $job->{nbd_socket});
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

done_testing();
