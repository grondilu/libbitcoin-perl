#!/usr/bin/perl
# elliptic curve cryptography in Perl
use v5.14;
use strict;
use warnings;
use bigint;
use integer;

package EC;

our ($a, $b, $p, $G);

sub Delta;
sub check;
sub double;
sub add;
sub mult;

sub import {
    import bigint;
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
	($a, $b, $p, $G) = map ${$EC::Curves::{$curve}}->{$_}, qw( a b p G );
	$G = bless $G, 'EC::Point';
	check $G;
    }
    else { die 'wrong import syntax' }
    die "curve parameters are not defined" unless defined $a and defined $b and defined $p;
    die "curve has nul discriminant" if Delta == 0;
}

sub Delta { -16*(4*$a**3 + 27*$b**2) }
sub check {
    my $u = shift;
    return $u unless $u;
    die "curve parameters are not defined" unless defined $a and defined $b and defined $p;
    die "curve has nul discriminant" if Delta == 0;
    die "point is not on elliptic curve" unless ($u->y**2 - $u->x**3 - $a*$u->x - $b) % $p == 0;
    return bless $u, 'EC::Point';
}
sub double {
    my $u = check shift;
    return $u unless $u;
    my $l = (3*$u->x**2 + $a) * (2 * $u->y)->bmodinv($p) % $p;
    my $x = $l**2 - 2*$u->x;
    my $y = $l*($u->x - ($x %= $p)) - $u->y;
    return bless { x => $x, y => $y % $p }, 'EC::Point';
}
sub add {
    my ($u, $v) = eval { map check($_), @_ };
    die "$@ in add" if $@;
    return $u unless $v;
    return $v unless $u;
    if ($u->x % $p == $v->x % $p) {
	return +($u->y + $v->y) % $p == 0 ?
	EC::Point->horizon :
	double $u
    }
    my $i = ($v->x - $u->x)->bmodinv($p);
    my $l = ($v->y - $u->y) * $i % $p;
    my $x = $l**2 - $u->x - $v->x;
    my $y = $l*($u->x - ($x %= $p)) - $u->y;
    return bless { x => $x, y => $y % $p }, 'EC::Point';
}
sub mult {
    my $k = shift;
    die "$k is not an integer" unless $k->isa('Math::BigInt');
    my $point = shift->clone;
    given($ENV{PERL_EC_METHOD}) {
	when(not defined or /perl/i) {
	    my $result = EC::Point->horizon;
	    for (; $k > 0; $point = double($point), $k /= 2) {
		$result += $point if $k%2 == 1;
	    }
	    return $result;
	}
	when(/dc/i) {
	    open my $dc, '-|', qw(dc -e), "
	    [[_1*lm1-*lm%q]Std0>tlm%Lts#]s%[Smddl%x-lm/rl%xLms#]s~[_1*l%x]s_[+l%x]s+[*l%x]
	    s*[-l%x]s-[l%xsclmsd1su0sv0sr1st[q]SQ[lc0=Qldlcl~xlcsdscsqlrlqlu*-ltlqlv*-lulv
	    stsrsvsulXx]dSXxLXs#LQs#lrl%x]sI[lpSm[+q]S0d0=0lpl~xsydsxd*3*lal+x2ly*lIx*l%xd
	    sld*2lx*l-xd lxrl-xlll*xlyl-xrlp*+Lms#L0s#]sD[lpSm[+q]S0[2;AlDxq]Sdd0=0rd0=0d2
	    :Alp~1:A0:Ad2:Blp~1:B0:B2;A2;B=d[0q]Sx2;A0;B1;Bl_xrlm*+=x0;A0;Bl-xlIxdsi1;A1;B
	    l-xl*xdsld*0;Al-x0;Bl-xd0;Arl-xlll*x1;Al-xrlp*+L0s#Lds#Lxs#Lms#]sA[rs.0r[rl.lA
	    xr]SP[q]sQ[d0!<Qd2%1=P2/l.lDxs.lLx]dSLxs#LPs#LQs#]sM
	    10i
	    $a sa $b sb $p dspsm
	    @{[$G->y, $G->x]} lp*+ dsG
	    @{[$k->bstr]} lMx 16olm~f
	    ";
	    my ($x, $y) = reverse map { chomp; hex $_ } <$dc>;
	    return bless { x => $x, y => $y }, ref $point;
	}
	default    {...}
    }
}

package EC::Point;
sub horizon { bless { x => 0, y => 0 }, shift }
sub clone { my $_ = shift; bless { x => $_->x, y => $_->y, order => $_->order }, ref $_ }
sub x { shift->{'x'} }
sub y { shift->{'y'} }
sub order { shift->{'order'} }
use overload
'bool' => sub { my $_ = shift; $_->x > 0 and $_->y > 0 },
'+' => sub { EC::add($_[0], $_[1]) },
'*' => sub { EC::mult($_[2] ? @_[1,0] : @_[0,1]) },
q("") => sub {
    use YAML;
    my $_ = shift;
    return
    $_ ?
    Dump {
	x => $_->x->as_hex, y => $_->y->as_hex,
	# order => defined($_->order) ? $_->order->bstr : 'non defined'
    } :
    'Point at horizon';
},
;

package Math::BigInt;
no overload '*';
use overload
'*' => sub {
    return $_[1]->isa('EC::Point') ? EC::mult($_[0], $_[1]) : $_[0]->copy->bmul($_[1]);
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
    my $point18 = 17 * $point + $point;

=head1 DESCRIPTION

This module provides functions to perform arithmetics in Elliptic Curves.

A small EC::Point class overloads addition, multiplication, boolean (to see if
the point is at horizon), and stringification operators.

This module DOES NOT perform ECDSA cryptography.  Use EC::DSA for that.

=head1 SEE ALSO

EC::DSA, EC::Curves

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
