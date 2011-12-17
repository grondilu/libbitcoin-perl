#!/usr/bin/perl
package EC::DSA;
use strict;
use warnings;
use integer;
use bigint;
use EC;

sub int_to_string {
    die "unexpected negative number" if (my $x = shift) < 0;
    return $x < 256 ? chr($x) : int_to_string($x/256).chr($x%256);
}
sub string_to_int {
    my $s = 0;
    for (split '', shift) { $s *= 256; $s += ord($_) }
    return $s;
}
sub point_is_valid {
    my ($G, $u) = map &EC::check, @_;
    my $n = $$G[2];
    die "out of range" if $$u[0] < 0 or $n <= $$u[0] or $$u[1] < 0 or $n <= $$u[1];
    die "wrong order" if defined @{EC::mult( $n, $u )};
}

sub digest_integer {
    use Digest::SHA qw(sha1);
    return string_to_int sha1 int_to_string shift  ;
}

1;
