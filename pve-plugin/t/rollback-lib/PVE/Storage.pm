package PVE::Storage;
# Stub for pve-plugin/rollback tests: volume `<store>:<name>` lives in
# $ENV{NEXUSBACKUP_TEST_PVE}/volumes/<name>; `.qcow2` names are qcow2, others raw;
# store `ceph` reports format `vmdk` (refused). Activations are appended to
# $ENV{NEXUSBACKUP_TEST_PVE}/activated.

use strict;
use warnings;

sub config { return {} }

sub parse_volname {
    my ($cfg, $volid) = @_;
    my ($store, $name) = $volid =~ m/^([a-z][a-z0-9\-_.]*):(.+)$/ or die "unable to parse volume ID '$volid'\n";
    my $fmt = $store eq 'ceph' ? 'vmdk' : $name =~ m/\.qcow2$/ ? 'qcow2' : 'raw';
    return ('images', $name, 100, undef, undef, 0, $fmt);
}

sub activate_volumes {
    my ($cfg, $vols) = @_;
    open(my $fh, '>>', "$ENV{NEXUSBACKUP_TEST_PVE}/activated") or die "$!\n";
    print {$fh} "$_\n" for @$vols;
    close($fh);
}

sub path {
    my ($cfg, $volid) = @_;
    my (undef, $name) = parse_volname($cfg, $volid);
    return "$ENV{NEXUSBACKUP_TEST_PVE}/volumes/$name";
}

1;
