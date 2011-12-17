#!/usr/bin/perl
# elliptic curve algebra in Perl
package EC;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(Delta add mult double);
use strict;
use warnings;
use integer;
use NumberTheory qw(inverse_mod);

use bigint;
our ($p, $a, $b);
sub init { ($p, $a, $b) = @_ }

sub Delta { -16*(4*$a**3 + 27*$b**2) }

sub check {
    my $u = shift;
    return $u unless @$u;
    die "curve parameters are not defined" unless defined $a and defined $b;
    die "curve has nul discriminant" if Delta == 0;
    die "point is not on elliptic curve" unless ($$u[1]**2 - $$u[0]**3 - $a*$$u[0] - $b) % $p == 0;
    return $u;
}
sub Cmp {
    my ($u, $v) = map { check $_ } @_;
    return !@$v ? !@$u : !@$u ? !@$v : $$u[0] == $$v[0] && $$u[1] == $$v[1];
}
sub double {
    my $u = check shift;
    return $u unless @$u;
    my $l = (3*$$u[0]**2 + $a) * inverse_mod(2 * $$u[1], $p) % $p;
    my $x = $l**2 - 2*$$u[0];
    return [ map { $_ % $p } $x, $l*($$u[0] - $x) - $$u[1] ];
}
sub add {
    my ($u, $v) = eval { map check($_), @_ };
    die "$@ in add" if $@;
    return $u unless @$v;
    return $v unless @$u;
    return +($$u[1] + $$v[1]) % $p == 0 ? [] : double $u if $$u[0] % $p == $$v[0] % $p;
    my $i = inverse_mod($$v[0] - $$u[0], $p);
    my $l = ($$v[1] - $$u[1]) * $i % $p;
    my $x = $l**2 - $$u[0] - $$v[0];
    return [ map { $_ % $p } $x, $l*($$u[0] - $x) - $$u[1] ];
}
sub mult {
    my $k = shift;
    my $u = check shift;
    $k %= $$u[2] if defined $$u[2];
    return [] if $k == 0 or !@$u;
    die "negative factor" if $k < 0;
    my $k3 = 3*$k;
    my $i = 1; $i *= 2 while $i <= $k3; $i /= 2;
    my $x = $u;
    while ( ($i/=2) > 1 ) {
	$x = double $x;
	$x = add $x, $u				if  ($k3 & $i) != 0 and ($k & $i) == 0;
	$x = add $x, [ $$u[0], -$$u[1] ]	if  ($k3 & $i) == 0 and ($k & $i) != 0;
    }
    return $x;
}

1;

