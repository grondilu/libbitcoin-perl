#!/usr/bin/perl
package EC::DSA::PrivateKey;
use strict;
use warnings;
use integer;
use bigint;
use EC;
use NumberTheory;

sub new {
    die "constructor's instance method call not implemented" if ref(my $class = shift);
    my ($public_key, $secret_multiplier) = @_;
    die "wront public key format" if ref($public_key) ne 'EC::DSA::PublicKey';
    bless [ $public_key, $secret_multiplier ], $class;
}
sub sign {
    die "class method call not implemented" unless ref(my $this = shift);
    my $n = $$this[0][0][2];
    my ($h, $random_k) = @_;
    my $k = $random_k % $n;
    my $p = EC::mult $k, $$this[0][0];
    my $r = $$p[0];
    die "amazingly unlucky random number r" if $r == 0;
    my $s = (
	NumberTheory::inverse_mod( $k, $n ) *
	($h + ($$this[1] * $r) % $n)
    ) % $n;
    die "amazingly unlucky random number s" if $s == 0;
    return [ $r, $s ];
}

1;
