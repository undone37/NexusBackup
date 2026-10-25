package PVE::LXC::Config;
# Stub for pve-plugin/rollback tests: container configurations as the VM stub
# (PVE::QemuConfig: JSON files, flock); mount points as `<volume>,mp=<path>[,backup=1]`.

use strict;
use warnings;

use PVE::QemuConfig;
use parent -norequire, 'PVE::QemuConfig';

sub foreach_volume {
    my ($class, $conf, $func) = @_;
    for my $ms (sort grep { m/^(?:rootfs|mp\d+)\z/ } keys %$conf) {
        my ($volume, @opts) = split(/,/, $conf->{$ms});
        $func->($ms, { volume => $volume, map { split(/=/, $_, 2) } @opts });
    }
    return;
}

sub mountpoint_backup_enabled {
    my ($class, $ms, $mp) = @_;
    return $ms eq 'rootfs' || $mp->{backup};
}

1;
