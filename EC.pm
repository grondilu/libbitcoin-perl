#!/usr/bin/perl
# elliptic curve algebra in Perl
package EC;
use strict;
use warnings;
use integer;
use NumberTheory qw(inverse_mod);

our ($a, $b, $p);

sub set_param;
sub Delta;
sub check;
sub Cmp;
sub double;
sub add;
sub mult;

sub import {
    my $class = shift;
    return unless @_;
    if (@_ > 1 and not @_ % 2) { $class->import( { @_ } ) }
    elsif (@_ == 1 and ref $_[0] eq 'HASH') {
	($a, $b, $p) = map $_[0]->{$_}, qw( a b p );
    }
    elsif (@_ == 1 and not ref $_[0]) {
	use EC::Curves;
	my $curve = shift;
	die 'unknown curve' unless exists $EC::Curves::{$curve};
	($a, $b, $p) = map ${$EC::Curves::{$curve}}->{$_}, qw( a b p );
    }
    else { die 'wrong import syntax' }
}

sub set_param {
    if (@_ > 1) { set_param { @_ } }
    else { ($a, $b, $p) = map $_[0]->{$_}, qw( a b p ) }
}

{
    use bigint;

    sub Delta { -16*(4*$a**3 + 27*$b**2) }
    sub check {
	my $u = shift;
	return $u unless @$u;
	die "curve parameters are not defined" unless defined $a and defined $b;
	die "curve has nul discriminant" if Delta == 0;
	die "point is not on elliptic curve" unless ($$u[1]**2 - $$u[0]**3 - $a*$$u[0] - $b) % $p == 0;
	return bless $u, 'EC::Point';
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
	return bless [ map { $_ % $p } $x, $l*($$u[0] - $x) - $$u[1] ], 'EC::Point';
    }
    sub add {
	my ($u, $v) = eval { map check($_), @_ };
	die "$@ in add" if $@;
	return $u unless @$v;
	return $v unless @$u;
	return +($$u[1] + $$v[1]) % $p == 0 ? bless [], 'EC::Point' : double $u if $$u[0] % $p == $$v[0] % $p;
	my $i = inverse_mod($$v[0] - $$u[0], $p);
	my $l = ($$v[1] - $$u[1]) * $i % $p;
	my $x = $l**2 - $$u[0] - $$v[0];
	return bless [ map { $_ % $p } $x, $l*($$u[0] - $x) - $$u[1] ], 'EC::Point';
    }
    sub mult {
	my $k = shift;
	my $u = check shift;
	$k %= $$u[2] if defined $$u[2];
	return bless [], 'EC::Point' if $k == 0 or not @$u;
	die "negative factor" if $k < 0;
	my $k3 = 3*$k;
	my $i = 1; $i *= 2 while $i <= $k3; $i /= 2;
	my $x = $u;
	while ( ($i/=2) > 1 ) {
	    $x = double $x;
	    $x = add $x, $u			if  ($k3 & $i) != 0 and ($k & $i) == 0;
	    $x = add $x, [ $$u[0], -$$u[1] ]	if  ($k3 & $i) == 0 and ($k & $i) != 0;
	}
	return $x;
    }
}

package EC::Point;
use overload
'+' => sub { bless EC::add @_[0..1] },
'*' => sub { die 'wrong argument order in multiplication' unless $_[2]; bless EC::mult @_[1,0] },
q("") => sub {
    my $_ = shift;
    return @$_ ?
    sprintf "Point at x=%s, y=%s", @$_[0,1] :
    'Point at horizon';
};

package EC::BigInt;
our @ISA = qw(Math::BigInt);
use overload
'*' => sub {
    return EC::mult $_[0], $_[1] if ref $_[1] eq 'EC::Point';
    $_[0]->bmul($_[1]);
};

1;

__END__

=head1 TITLE

EC - Elliptic Curve calculations in Perl

=head1 SYNOPSIS

    use EC qw( a 0 b 2 p 193 );
    # or
    use EC qw( secp256k1 );

    my $point = EC::check [ 1, 14 ];
    $point = EC::double $point;
    $point = EC::mult 7, $point;
    $point = EC::add $point, EC::double $point;
    bless $point, 'Point';
    my $point18 = 17 * $point + $point;

=head1 DESCRIPTION

This module provides functions to perform arithmetics in Elliptic Curves.

A point is just a blessed reference to an array of integers, the third, optionnal one,
being the order.  A point at the infinite is a reference to the empty array.

A small EC::Point class can be used to bless points and handle them using overloaded
addition, multiplication and stringification operators.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
