#!/usr/bin/perl
# Tests for pve-plugin/helper: argument validation, job/done/put-index and the
# full-duplex nbd pipe. Uses the test-only NEXUSBACKUP_RUNDIR/STATEDIR overrides.
use strict;
use warnings;

use Digest::MD5 qw(md5_hex);
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use IPC::Open3 qw(open3);
use JSON;
use POSIX ();
use Socket qw(SOCK_STREAM SHUT_WR);
use Symbol qw(gensym);
use Test::More;

my $helper = dirname(__FILE__) . "/../helper";
my $tmp = tempdir(CLEANUP => 1);
my $rundir = "$tmp/jobs";
my $statedir = "$tmp/state";
mkdir($rundir) or die;
mkdir($statedir) or die;
mkdir("$statedir/nexus") or die;

$ENV{NEXUSBACKUP_RUNDIR} = $rundir;
$ENV{NEXUSBACKUP_STATEDIR} = $statedir;
delete $ENV{SSH_CONNECTION};
delete $ENV{SSH_ORIGINAL_COMMAND};
$SIG{PIPE} = "IGNORE";

# Run the helper; returns (exit code, stdout, stderr).
sub run_helper {
    my (%o) = @_;
    local $ENV{SSH_ORIGINAL_COMMAND} = $o{cmd} if defined($o{cmd});
    local $ENV{SSH_CONNECTION} = $o{ssh} if defined($o{ssh});
    my $err = gensym;
    my $pid = open3(my $in, my $out, $err, $^X, $helper, @{ $o{args} // [] });
    binmode($in);
    binmode($out);
    print {$in} $o{stdin} if defined($o{stdin});
    close($in);
    my $stdout = do { local $/; <$out> } // '';
    my $stderr = do { local $/; <$err> } // '';
    waitpid($pid, 0);
    return ($? >> 8, $stdout, $stderr);
}

sub code { (run_helper(@_))[0] }

# --- argument validation -------------------------------------------------
my @invalid = (
    '', 'ls', 'job', 'job abc', 'job 1234567890', 'job -1', 'job 100 101', 'job ../100',
    'nbd', 'nbd 1a', 'nbd 100 x', 'done', 'done 100', 'done 100 maybe', 'done x ok',
    'done 100 ok extra', 'done 100 fail', 'put-index', 'put-index Nexus', 'put-index n',
    'put-index ../etc', 'put-index nexus extra', 'put-index 1abc', 'job 100;id',
    'put-index ' . ('a' x 101), 'JOB 100', 'scp -t /tmp',
);
for my $c (@invalid) {
    is(code(cmd => $c), 2, "rejects '$c' (SSH_ORIGINAL_COMMAND)");
}
is(code(args => ['job', "100\n"]), 2, 'rejects vmid with trailing newline');
is(code(args => ['bogus']), 2, 'rejects unknown command via argv');
is(code(ssh => '1.2.3.4 1 5.6.7.8 22'), 2, 'rejects empty command under sshd');
is(code(cmd => 'job 100', ssh => '1.2.3.4 1 5.6.7.8 22'), 1,
    'under sshd test overrides are ignored (real /run path, no job)');

# --- job / done ------------------------------------------------------------
is(code(cmd => 'job 100'), 1, 'job: exit 1 while no job is present');
is(code(cmd => 'done 100 ok'), 1, 'done: exit 1 while no job is present');
ok(!-e "$rundir/100.done", 'no done file written without a job');

sub write_job {
    my ($vmid, $sock) = @_;
    my $job = {
        vmid => $vmid + 0, archive => "nexus-$vmid-1760000000", nbd_socket => $sock,
        devices => [{ name => 'drive-scsi0', size => 1 << 30, bitmap_mode => 'new',
            bitmap_name => 'snapshot-access:nexus' }],
        config => "memory: 1024\n", firewall => undef,
    };
    my $raw = JSON->new->canonical->encode($job) . "\n";
    open(my $fh, '>', "$rundir/$vmid.json") or die;
    print {$fh} $raw;
    close($fh);
    return $raw;
}

my $sock_path = "$tmp/nbd.sock";
my $job_raw = write_job(100, $sock_path);
my ($rc, $out) = run_helper(cmd => 'job 100');
is($rc, 0, 'job: exit 0');
is($out, $job_raw, 'job: prints job JSON verbatim');

is(code(cmd => 'done 100 ok'), 0, 'done ok');
is(slurp("$rundir/100.done"), "ok\n", 'done file says ok');
is(code(cmd => "done 100 fail read error on drive-scsi0\x01"), 0, 'done fail');
is(slurp("$rundir/100.done"), "fail read error on drive-scsi0\n", 'done file has sanitized message');
is(code(args => ['done', '100', 'ok']), 0, 'done via argv');
my @left = glob("$rundir/.*done*");
is(scalar(@left), 0, 'no temp files left behind');

sub slurp {
    my ($f) = @_;
    open(my $fh, '<', $f) or return undef;
    local $/;
    return <$fh>;
}

# --- put-index ---------------------------------------------------------------
my $index = '{"version":1,"archives":[{"volname":"backup/nexus-100-1760000000","vmid":100}]}';
is(code(cmd => 'put-index nexus', stdin => $index), 0, 'put-index valid');
is(slurp("$statedir/nexus/index.json"), $index, 'index written');
is((stat("$statedir/nexus/index.json"))[2] & 07777, 0640, 'index mode 0640');
is(code(cmd => 'put-index nexus', stdin => '{"archives":[ broken'), 1, 'put-index invalid JSON');
is(code(cmd => 'put-index nexus', stdin => '[1,2]'), 1, 'put-index non-object');
is(code(cmd => 'put-index nexus', stdin => '{"version":1}'), 1, 'put-index without archives');
is(slurp("$statedir/nexus/index.json"), $index, 'index unchanged after rejected pushes');
is(code(cmd => 'put-index other', stdin => $index), 1, 'put-index for missing storage dir');
{
    my $big = '{"archives":[],"pad":"' . ('x' x (64 * 1024 * 1024)) . '"}';
    is(code(cmd => 'put-index nexus', stdin => $big), 1, 'put-index > 64 MiB rejected');
    is(slurp("$statedir/nexus/index.json"), $index, 'index unchanged after oversized push');
}
@left = glob("$statedir/nexus/.index*");
is(scalar(@left), 0, 'no index temp files left behind');

# --- nbd pipe ----------------------------------------------------------------
# Server: sends a greeting first (like NBD's "NBDMAGIC"), then echoes until EOF,
# then closes. Exercises both directions concurrently.
sub start_server {
    my ($mode) = @_;
    unlink($sock_path);
    my $listen = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $sock_path, Listen => 1)
        or die "listen: $!";
    my $pid = fork() // die;
    if ($pid == 0) {
        my $c = $listen->accept() or POSIX::_exit(3);
        binmode($c);
        syswrite($c, "NBDMAGICIHAVEOPT");
        if ($mode eq 'echo') {
            my $buf;
            while (1) {
                my $n = sysread($c, $buf, 65536);
                last if !$n;
                my $off = 0;
                while ($off < $n) {
                    my $w = syswrite($c, $buf, $n - $off, $off) // POSIX::_exit(4);
                    $off += $w;
                }
            }
        }
        close($c);
        POSIX::_exit(0);
    }
    close($listen);
    return $pid;
}

{
    my $srv = start_server('echo');
    my $err = gensym;
    local $ENV{SSH_ORIGINAL_COMMAND} = 'nbd 100';
    my $pid = open3(my $in, my $out, $err, $^X, $helper);
    binmode($in);
    binmode($out);

    my $size = 12 * 1024 * 1024 + 12345;
    my $data = join('', map { pack('N', int(rand(2**32))) } 1 .. ($size / 4 + 1));
    $data = substr($data, 0, $size);

    my $writer = fork() // die;
    if ($writer == 0) {
        close($out);
        my $off = 0;
        while ($off < length($data)) {
            my $w = syswrite($in, $data, 1 << 20, $off) // POSIX::_exit(1);
            $off += $w;
        }
        close($in);
        POSIX::_exit(0);
    }
    close($in);

    my $got = '';
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm(60);
    my $ok = eval {
        while (1) {
            my $n = sysread($out, $got, 1 << 20, length($got));
            die "read: $!" if !defined($n);
            last if $n == 0;
        }
        1;
    };
    alarm(0);
    ok($ok, 'nbd: stdout reached EOF after stdin EOF') or diag($@);
    waitpid($writer, 0);
    waitpid($pid, 0);
    is($? >> 8, 0, 'nbd: helper exit 0');
    waitpid($srv, 0);
    is($? >> 8, 0, 'nbd: server saw clean EOF');
    is(substr($got, 0, 16), 'NBDMAGICIHAVEOPT', 'nbd: server greeting arrives first');
    is(length($got) - 16, $size, 'nbd: echoed length matches (' . $size . ' bytes)');
    ok(md5_hex(substr($got, 16)) eq md5_hex($data), 'nbd: echoed data identical');
}

{
    # server closes first while the client keeps stdin open: helper must exit
    my $srv = start_server('close');
    my $err = gensym;
    local $ENV{SSH_ORIGINAL_COMMAND} = 'nbd 100';
    my $pid = open3(my $in, my $out, $err, $^X, $helper);
    binmode($out);
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm(20);
    my $got = eval { local $/; <$out> };
    my $exited = eval { waitpid($pid, 0); 1 };
    alarm(0);
    ok($exited, 'nbd: helper exits when the server closes, stdin still open');
    is($got, 'NBDMAGICIHAVEOPT', 'nbd: got greeting before server close');
    close($in);
    waitpid($srv, 0);
}

{
    unlink($sock_path);
    my ($rc) = run_helper(cmd => 'nbd 100');
    is($rc, 1, 'nbd: exit 1 when the socket is gone');
    is(code(cmd => 'nbd 101'), 1, 'nbd: exit 1 without job');
}

# --- restore-job / restore-serve ---------------------------------------------
my $restoredir = "$tmp/restore";
mkdir($restoredir) or die;
$ENV{NEXUSBACKUP_RESTOREDIR} = $restoredir;
my $archive = 'nexus-100-1760000000';

for my $c ('restore-job', 'restore-job nexus-100', 'restore-job vzdump-100-1', 'restore-job ../x',
    "restore-job $archive extra", "restore-serve $archive", "restore-serve $archive Drive",
    "restore-serve $archive drive/scsi0", "restore-serve $archive ../x", 'restore-serve x drive-scsi0',
    "restore-serve $archive drive-scsi0 x", "restore-serve $archive " . ('a' x 65),
    'restore-job nexus-1234567890-1') {
    is(code(cmd => $c), 2, "rejects '$c'");
}
is(code(cmd => "restore-job $archive"), 1, 'restore-job: exit 1 without request');
is(code(cmd => "restore-serve $archive drive-scsi0"), 1, 'restore-serve: exit 1 without request');

my $rsock = "$restoredir/$archive.drive-scsi0.sock";
my $req = JSON->new->canonical->encode({ archive => $archive, device => 'drive-scsi0', socket => $rsock }) . "\n";
open(my $rfh, '>', "$restoredir/$archive.json") or die;
print {$rfh} $req;
close($rfh);
($rc, $out) = run_helper(cmd => "restore-job $archive");
is($rc, 0, 'restore-job: exit 0');
is($out, $req, 'restore-job: prints request');
is(code(cmd => "restore-serve $archive drive-efidisk0"), 1, 'restore-serve: wrong device refused');

{
    my $err = gensym;
    local $ENV{SSH_ORIGINAL_COMMAND} = "restore-serve $archive drive-scsi0";
    my $pid = open3(my $in, my $out, $err, $^X, $helper);
    binmode($in);
    binmode($out);

    my $client;
    for (1 .. 100) {
        last if -S $rsock;
        select(undef, undef, undef, 0.05);
    }
    ok(-S $rsock, 'restore-serve: socket published');
    is((stat($rsock))[2] & 0777, 0660, 'restore-serve: socket mode 0660');
    $client = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $rsock);
    ok($client, 'restore-serve: client (qemu-nbd role) connects');
    binmode($client);
    for (1 .. 50) {
        last if !-e $rsock;
        select(undef, undef, undef, 0.05);
    }
    ok(!-e $rsock, 'restore-serve: socket removed after the one accept');

    my $size = 10 * 1024 * 1024 + 7;
    my $up = join('', map { pack('N', int(rand(2**32))) } 1 .. ($size / 4 + 1));
    $up = substr($up, 0, $size);
    my $down = reverse($up);

    # client -> helper stdout (the appliance's NBD requests direction)
    my $cw = fork() // die;
    if (!$cw) {
        close($out);
        my $off = 0;
        while ($off < length($up)) {
            $off += syswrite($client, $up, 1 << 20, $off) // POSIX::_exit(1);
        }
        POSIX::_exit(0);
    }
    # appliance -> helper stdin -> client
    my $aw = fork() // die;
    if (!$aw) {
        close($out);
        my $off = 0;
        while ($off < length($down)) {
            $off += syswrite($in, $down, 1 << 20, $off) // POSIX::_exit(1);
        }
        close($in);
        POSIX::_exit(0);
    }
    close($in);

    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm(60);
    my ($got_up, $got_down) = ('', '');
    my $ok = eval {
        my $rpid = fork() // die;
        if (!$rpid) {
            # read what the client receives; report its digest via exit code path
            my $buf = '';
            while (length($buf) < $size) {
                my $n = sysread($client, $buf, 1 << 20, length($buf));
                last if !$n;
            }
            POSIX::_exit(md5_hex($buf) eq md5_hex($down) ? 0 : 1);
        }
        while (length($got_up) < $size) {
            my $n = sysread($out, $got_up, 1 << 20, length($got_up));
            die "read: $!" if !defined($n);
            last if $n == 0;
        }
        waitpid($rpid, 0);
        is($? >> 8, 0, 'restore-serve: client received the appliance stream intact');
        1;
    };
    ok($ok, 'restore-serve: no deadlock') or diag($@);
    is(md5_hex($got_up), md5_hex($up), 'restore-serve: appliance received the client stream intact');
    waitpid($cw, 0);
    waitpid($aw, 0);
    close($client); # qemu-nbd -d
    my $rest = eval { local $/; <$out> };
    my $exited = eval { waitpid($pid, 0); 1 };
    alarm(0);
    ok($exited, 'restore-serve: exits after the client disconnects');
    is($? >> 8, 0, 'restore-serve: exit 0');
    ok(!defined($rest) || $rest eq '', 'restore-serve: no trailing output');
}

done_testing();
