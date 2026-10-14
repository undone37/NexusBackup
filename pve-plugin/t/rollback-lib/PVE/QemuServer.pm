package PVE::QemuServer;
# Stub for pve-plugin/rollback tests: a VM runs while
# $ENV{NEXUSBACKUP_TEST_PVE}/<vmid>.running exists.

use strict;
use warnings;

sub check_running {
    my ($vmid) = @_;
    return -e "$ENV{NEXUSBACKUP_TEST_PVE}/$vmid.running" ? 1 : 0;
}

1;
