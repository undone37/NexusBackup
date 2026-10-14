package PVE::QemuConfig;
# Stub for pve-plugin/rollback tests: VM configurations are JSON files in
# $ENV{NEXUSBACKUP_TEST_PVE}/<vmid>.json; the config lock is an flock.

use strict;
use warnings;

use Fcntl qw(:flock);
use JSON;

sub dir { $ENV{NEXUSBACKUP_TEST_PVE} // die "NEXUSBACKUP_TEST_PVE not set\n" }

sub lock_config {
    my ($class, $vmid, $code) = @_;
    open(my $fh, '>>', dir() . "/$vmid.lock") or die "lock: $!\n";
    flock($fh, LOCK_EX) or die "lock: $!\n";
    my $r = $code->();
    close($fh);
    return $r;
}

sub load_config {
    my ($class, $vmid) = @_;
    open(my $fh, '<', dir() . "/$vmid.json") or die "Configuration file 'nodes/pve1/qemu-server/$vmid.conf' does not exist\n";
    local $/;
    return decode_json(<$fh>);
}

sub write_config {
    my ($class, $vmid, $conf) = @_;
    open(my $fh, '>', dir() . "/$vmid.json") or die "write: $!\n";
    print {$fh} JSON->new->canonical->encode($conf);
    close($fh) or die "write: $!\n";
}

1;
