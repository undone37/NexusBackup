#!/usr/bin/perl
# Tests for pve-plugin/rollback (the root side of the in-place rollback, Phase 30)
# against stub PVE modules (t/rollback-lib), and for the helper's rollback-*
# commands through a socket-activation stand-in (one rollback process per
# connection, like nexusbackup-rollback.socket with Accept=yes). Needs qemu-nbd
# for the NBD part (skipped without it); the data path itself is tested from the
# appliance side in crates/pve/tests/rollback.rs.
use strict;
use warnings;

use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use IPC::Open3 qw(open3);
use JSON;
use POSIX ();
use Socket qw(SOCK_STREAM);
use Symbol qw(gensym);
use Test::More;

my $here = dirname(__FILE__);
my $rollback = "$here/../rollback";
my $helper = "$here/../helper";
my $tmp = tempdir(CLEANUP => 1);
my $pve = "$tmp/pve";
mkdir($pve) or die;
mkdir("$pve/volumes") or die;
$ENV{NEXUSBACKUP_TEST_PVE} = $pve;
$ENV{NEXUSBACKUP_ROLLBACK_RUNDIR} = "$tmp/run";
$ENV{PERL5LIB} = "$here/rollback-lib";
delete $ENV{SSH_CONNECTION};
delete $ENV{SSH_ORIGINAL_COMMAND};
$SIG{PIPE} = 'IGNORE';

sub conf {
    my ($vmid, $c) = @_;
    open(my $fh, '>', "$pve/$vmid.json") or die;
    print {$fh} encode_json($c);
    close($fh);
}

sub load {
    my ($vmid) = @_;
    open(my $fh, '<', "$pve/$vmid.json") or die;
    local $/;
    return decode_json(<$fh>);
}

# One request to the rollback program; (exit code, output).
sub request {
    my ($line) = @_;
    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, $^X, $rollback);
    print {$in} $line;
    close($in);
    my $o = do { local $/; <$out> } // '';
    waitpid($pid, 0);
    return ($? >> 8, $o);
}

my $disk = "$pve/volumes/vm-100-disk-0";
open(my $d, '>', $disk) or die;
truncate($d, 4 << 20);
close($d);
my $base = { name => 'web', scsi0 => 'local:vm-100-disk-0,size=4M', ide2 => 'local:iso/x.iso,media=cdrom',
    sata1 => 'ceph:vm-100-disk-1,size=4M', tags => 'prod;nexus-rollback' };

# --- request validation --------------------------------------------------------
for my $bad ("bogus 100\n", "begin x\n", "begin 100 101\n", "nbd 100 scsi0\n", "nbd 100 drive-tpmstate0\n",
    "nbd 100 drive-scsi0 x\n", "end\n", "\n", 'begin 100') {
    my ($rc, $o) = request($bad);
    is($rc, 1, "rejects " . ($bad =~ s/\n/\\n/gr));
    like($o, qr/^error /, 'answers with an error line');
}

# --- begin / end -----------------------------------------------------------------
conf(100, { %$base, tags => 'prod' });
my ($rc, $o) = request("begin 100\n");
is($rc, 1, 'begin: refused without the tag');
like($o, qr/not marked for a rollback/, 'reason: tag');
conf(100, $base);
open(my $r, '>', "$pve/100.running") or die;
close($r);
($rc, $o) = request("begin 100\n");
like($o, qr/is running/, 'begin: refused while running');
unlink("$pve/100.running");
conf(100, { %$base, lock => 'backup' });
($rc, $o) = request("begin 100\n");
like($o, qr/locked \(backup\)/, 'begin: refused with a foreign lock');
conf(100, $base);
($rc, $o) = request("nbd 100 drive-scsi0\n");
like($o, qr/not locked for a rollback/, 'nbd: refused before begin');
($rc, $o) = request("begin 100\n");
is($rc, 0, 'begin ok');
is($o, "ok locked\n", 'begin answers ok locked');
is(load(100)->{lock}, 'rollback', 'lock rollback set');
($rc, $o) = request("begin 100\n");
is($o, "ok resumed\n", 'a second begin resumes an interrupted rollback');

# --- nbd ---------------------------------------------------------------------------
($rc, $o) = request("nbd 100 drive-ide2\n");
like($o, qr/CD-ROM/, 'nbd: refuses a CD-ROM');
($rc, $o) = request("nbd 100 drive-scsi5\n");
like($o, qr/has no disk scsi5/, 'nbd: refuses a missing disk');
($rc, $o) = request("nbd 100 drive-sata1\n");
like($o, qr/format vmdk is not supported/, 'nbd: refuses other formats');
SKIP: {
    skip 'qemu-nbd not installed', 3 if !-x '/usr/bin/qemu-nbd';
    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, $^X, $rollback);
    binmode($in);
    binmode($out);
    syswrite($in, "nbd 100 drive-scsi0\n");
    my $line = '';
    while (sysread($out, my $c, 1)) {
        last if $c eq "\n";
        $line .= $c;
    }
    is($line, 'ok raw', 'nbd: ok with the format');
    my $got = '';
    sysread($out, $got, 16);
    is($got, 'NBDMAGICIHAVEOPT', 'nbd: the NBD greeting of qemu-nbd follows');
    close($in);
    close($out);
    waitpid($pid, 0);
    like(do { open(my $a, '<', "$pve/activated") or die; local $/; <$a> }, qr/^local:vm-100-disk-0$/m,
        'nbd: the volume was activated');
}

($rc, $o) = request("end 100\n");
is($o, "ok unlocked\n", 'end ok');
ok(!exists load(100)->{lock}, 'lock removed');
is(load(100)->{name}, 'web', 'the rest of the configuration is untouched');
conf(100, { %$base, lock => 'backup' });
($rc, $o) = request("end 100\n");
is(load(100)->{lock}, 'backup', 'end leaves a foreign lock alone');

# --- helper -> service ---------------------------------------------------------------
my $sock = "$tmp/rollback.sock";
my $listen = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $sock, Listen => 4) or die "listen: $!";
my $service = fork() // die;
if ($service == 0) {
    # systemd Accept=yes stand-in: one rollback process per connection, stdio = connection
    while (my $c = $listen->accept()) {
        my $p = fork() // POSIX::_exit(1);
        if ($p == 0) {
            open(STDIN, '<&', $c) or POSIX::_exit(1);
            open(STDOUT, '>&', $c) or POSIX::_exit(1);
            exec($^X, $rollback) or POSIX::_exit(1);
        }
        close($c);
    }
    POSIX::_exit(0);
}
close($listen);
$ENV{NEXUSBACKUP_ROLLBACK_SOCK} = $sock;

sub helper {
    my ($cmd) = @_;
    local $ENV{SSH_ORIGINAL_COMMAND} = $cmd;
    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, $^X, $helper);
    close($in);
    my $o = do { local $/; <$out> } // '';
    my $e = do { local $/; <$err> } // '';
    waitpid($pid, 0);
    return ($? >> 8, $o, $e);
}

for my $bad ('rollback-begin', 'rollback-begin x', 'rollback-begin 100 101', 'rollback-nbd 100',
    'rollback-nbd 100 scsi0', 'rollback-nbd 100 drive-tpmstate0', 'rollback-end 1a', 'rollback-nbd 100 drive-scsi0;id') {
    is((helper($bad))[0], 2, "helper rejects '$bad'");
}
conf(100, $base);
my ($hc, $ho, $he) = helper('rollback-begin 100');
is($hc, 0, 'helper rollback-begin: exit 0');
is($ho, "ok locked\n", 'helper prints the service answer');
($hc, $ho, $he) = helper('rollback-nbd 100 drive-ide2');
is($hc, 1, 'helper rollback-nbd: exit 1 on a refusal');
like($he, qr/CD-ROM/, 'with the reason on stderr');
($hc, $ho) = helper('rollback-end 100');
is($ho, "ok unlocked\n", 'helper rollback-end');
conf(100, { %$base, tags => '' });
($hc, $ho, $he) = helper('rollback-begin 100');
is($hc, 1, 'helper rollback-begin: refused without the tag');
kill('TERM', $service);
waitpid($service, 0);
{
    local $ENV{NEXUSBACKUP_ROLLBACK_SOCK} = "$tmp/none.sock";
    ($hc, $ho, $he) = helper('rollback-begin 100');
    is($hc, 1, 'helper: exit 1 without the service');
    like($he, qr/nexusbackup-rollback\.socket/, 'names the socket unit');
}

done_testing();
