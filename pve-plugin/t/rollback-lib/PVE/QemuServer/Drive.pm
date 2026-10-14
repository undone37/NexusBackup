package PVE::QemuServer::Drive;
# Stub for pve-plugin/rollback tests: `<volid>[,key=value…]` like qemu-server's
# disk properties (file, media).

use strict;
use warnings;

sub parse_drive {
    my ($key, $value) = @_;
    return undef if !defined($value) || $value eq '';
    my ($file, @kv) = split(/,/, $value);
    my $d = { interface => $key };
    if ($file =~ m/^file=(.*)$/) {
        $d->{file} = $1;
    } else {
        $d->{file} = $file;
    }
    for (@kv) {
        my ($k, $v) = split(/=/, $_, 2);
        return undef if !defined($v);
        $d->{$k} = $v;
    }
    return $d;
}

1;
