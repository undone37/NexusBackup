package PVE::LXC;
# Stub for pve-plugin/rollback tests: a container runs while
# $ENV{NEXUSBACKUP_TEST_PVE}/<vmid>.running exists; its root file system is the
# directory ct-<vmid>-root there (mount_all / umount_all only record the calls);
# no id mapping (the test runs unprivileged as itself).

use strict;
use warnings;

sub dir { $ENV{NEXUSBACKUP_TEST_PVE} // die "NEXUSBACKUP_TEST_PVE not set\n" }

sub check_running {
    my ($vmid) = @_;
    return -e dir() . "/$vmid.running";
}

sub parse_id_maps {
    my ($conf) = @_;
    return ([], 0, 0);
}

sub userns_command {
    my ($id_map) = @_;
    return [];
}

sub mount_all {
    my ($vmid, $storecfg, $conf) = @_;
    my $root = dir() . "/ct-$vmid-root";
    die "no root file system\n" if !-d $root;
    open(my $fh, '>>', dir() . "/mounted") or die;
    print {$fh} "$vmid\n";
    close($fh);
    return $root;
}

sub umount_all {
    my ($vmid, $storecfg, $conf, $noerr) = @_;
    open(my $fh, '>>', dir() . "/unmounted") or die;
    print {$fh} "$vmid\n";
    close($fh);
    return;
}

1;
