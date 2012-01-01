#!/usr/bin/perl
package EC::DSA::PublicKey;
use strict;
use warnings;
use integer;
use bigint;
use EC;
use NumberTheory;

sub new {
    die "constructor's instance method call not implemented" if ref(my $class = shift);
    my ($generator, $point) = @_;
    die "generator should have an order" unless defined(my $n = $$generator[2]);
    die "bad order for generator" if defined EC::mult $n, $generator;
    bless [ map EC::check($_), $generator, $point ], $class;
}
sub verifies {
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

1;
