#!/usr/bin/perl
# elliptic curve cryptography in Perl


package EC::Curves;
use strict;
use warnings;
use bigint;

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
use constant secp256k1 => {
    p => hex('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
    b => hex('0x0000000000000000000000000000000000000000000000000000000000000007'),
    a => hex('0x0000000000000000000000000000000000000000000000000000000000000000'),
    G => bless [
	hex('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'),
	hex('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
	hex('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
    ], 'Point'
};

no bigint;

package EC;
use strict;
use warnings;
use integer;
use NumberTheory qw(inverse_mod);

our ($a, $b, $p);

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
	my $curve = shift;
	die 'unknown curve' unless exists $EC::Curves::{$curve};
	($a, $b, $p) = map ${$EC::Curves::{$curve}}->{$_}, qw( a b p );
    }
    else { die 'wrong import syntax' }
    die "curve parameters are not defined" unless defined $a and defined $b and defined $p;
    die "curve has nul discriminant" if Delta == 0;
}

{
    use bigint;

    sub Delta { -16*(4*$a**3 + 27*$b**2) }
    sub check {
	my $u = shift;
	return $u unless @$u;
	die "curve parameters are not defined" unless defined $a and defined $b and defined $p;
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

package EC::DSA::PublicKey;
use strict;
use warnings;

sub new {
    die "constructor's instance method call not implemented" if ref(my $class = shift);
    my ($generator, $point) = @_;
    die "generator should have an order" unless defined(my $n = $$generator[2]);
    die "bad order for generator" if defined EC::mult $n, $generator;
    bless [ map EC::check($_), $generator, $point ], $class;
}
sub verifies {
    use bigint;
    my $this = shift;
    die "class method call not implemented" unless ref $this;
    my $n = $this->[0][2];
    my $h = shift;
    my ($r, $s) = @{shift()};
    die "out of range" if $r < 1 or $r > $n - 1 or $s < 1 or $s > $n -1;
    my $c = NumberTheory::inverse_mod($s, $n);
    my @u = map { $_*$c % $n } $h, $r;
    my $xy = EC::add map EC::mult( $u[$_], $this->[$_] ), 0, 1;
    die "wrong signature" unless $$xy[0] % $n == $r;
}

package EC::DSA::PrivateKey;
use strict;
use warnings;
use integer;

sub new {
    die "constructor's instance method call not implemented" if ref(my $class = shift);
    my ($public_key, $secret_multiplier) = @_;
    die "wrong public key format" if ref($public_key) ne 'EC::DSA::PublicKey';
    bless [ $public_key, $secret_multiplier ], $class;
}
sub sign {
    use bigint;
    my $_ = shift;
    die "class method call not implemented" unless ref;
    my $generator = $_->[0][0];
    my $n = $generator->[2] // die 'unknown generator order';
    my ($h, $random_k) = @_;
    my $k = $random_k % $n;
    my $p = EC::mult $k, $generator;
    my $r = $$p[0];
    die "amazingly unlucky random number r" if $r == 0;
    my $s = (
	NumberTheory::inverse_mod( $k, $n ) *
	($h + ($$_[1] * $r) % $n)
    ) % $n;
    die "amazingly unlucky random number s" if $s == 0;
    return [ $r, $s ];
}

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
    my $point18 = 17 * $point + $point;

=head1 DESCRIPTION

This module provides functions to perform arithmetics in Elliptic Curves.

A point is just a blessed reference to an array of integers, the third, optionnal one,
being the order.  A point at the infinite is a reference to the empty array.

A small EC::Point class overloads addition, multiplication and stringification operators.

This module DOES NOT perform ECDSA cryptography.  See EC::DSA.

=head1 SEE ALSO

EC::DSA, EC::Curves

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
