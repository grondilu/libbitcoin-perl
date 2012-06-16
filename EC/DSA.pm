#!/usr/bin/perl
use strict;
use warnings;
use bigint;

package EC::DSA;
use EC;

# EC::DSA should import the same things as EC
sub import { EC::import(@_) }

package EC::DSA::PublicKey;
our @ISA = qw(EC::Point);
use strict;
use warnings;
use overload '&{}' => sub { my $this = shift; sub { $this->verify(@_) } };

sub verify {
    use NumberTheory q(inverse_mod);
    my $this = shift;
    die "class method call not implemented" unless ref $this;
    my $n = $EC::G->order;
    my ($h, $r, $s) = @_;
    die "out of range" if $r < 1 or $r > $n - 1 or $s < 1 or $s > $n -1;
    my $c = inverse_mod($s, $n);
    my @u = map { $_*$c % $n } $h, $r;
    my $xy = $u[0] * $EC::G  +  $u[1] * $this;
    die "wrong signature" unless $xy->x % $n == $r;
}
sub serialize { 
    my $this = shift;
    $this->EC::DSA::PublicKey::UnCompressed::serialize(@_);
}

package EC::DSA::PublicKey::UnCompressed;
our @ISA = qw(EC::DSA::PublicKey);
sub serialize { 
    my $this = shift;
    return pack 'H2H*H*',
    '04', map { uc $_->badd(2**256)->as_hex =~ s/0x1//r } $this->x, $this->y;
}
sub compress {
    my $this = shift;
    bless ref($this) ? $this : shift, 'EC::DSA::PublicKey::Compressed';
}

package EC::DSA::PublicKey::Compressed;
our @ISA = qw(EC::DSA::PublicKey);
sub serialize { 
    my $this = shift;
    return pack 'H2H*H2',
    '03', map { uc +(2**256+$_)->as_hex =~ s/0x1//r } $this->x, $this->y % 2 == 0 ? 2 : 3;
}

package EC::DSA::PrivateKey;
require Math::BigInt;
our @ISA = qw(Math::BigInt);
use strict;
use warnings;
use integer;

sub sign {
    use Bitcoin::Util;
    my $_ = shift;
    die "class method call not implemented" unless ref;
    my $h = shift // die 'nothing to sign';
    my $random_k = shift // Bitcoin::Util::randInt;
    my $k = $random_k % (my $n = $EC::G->order);
    my $p = $k * $EC::G;
    my $r = $p->x;
    die "amazingly unlucky random number r" if $r == 0;
    my $s = ( NumberTheory::inverse_mod( $k, $n ) * ($h + ($_ * $r) % $n) ) % $n;
    die "amazingly unlucky random number s" if $s == 0;
    return $r, $s;
}
sub public_key {
    my $this = shift;
    die "class method call not implemented" unless ref $this;
    return bless $this * $EC::G, 'EC::DSA::PublicKey';
}
sub random {
    my $this = shift;
    my $i = 0;
    $i = 256*$i + int rand 256 for 1..32;
    $this->new($i);
}

# Elliptic curve DSA private keys should obey modular arithmetics
no overload qw(* + - /);
use overload
'+'	=>	sub { $_[0]->copy()->badd($_[1])->bmod($EC::G->{order}); },
'*'	=>	sub {
    my ($self, $other) = @_[$_[2] ? (1,0) : (0, 1)];
    return
    $other->isa('EC::Point') ?
    EC::mult($self, $other) :
    $self->copy()->bmul($other)->bmod($EC::G->{order}) ;
},
'-'	=>	sub { $_[0]->copy()->bsub($_[1])->bmod($EC::G->{order}); },
'/'	=>	sub { 
   return $_[2] ?
   ref($_[0])->new($_[1])->bmul($_[0]->copy->bmodinv($EC::G->{order})) :
   $_[0]->copy->bmul($_[1]->copy->bmodinv($EC::G->{order}));
  }, 
;

package EC::DSA::ASN;
use Convert::ASN1;
our $Signature = new Convert::ASN1;
prepare $Signature q(
    SEQUENCE {
	r INTEGER,
	s INTEGER
    }
);

1;

__END__

=head1 SYNOPSIS

    use EC::DSA q(secp256k1);

    my $privkey = new EC::DSA::PrivateKey  584738912309;
    my $privkey = random EC::DSA::Privatekey;
    my $pubkey  = $privkey->public_key;
    my ($r, $s) = $privkey->sign($some_message_digest_as_an_integer);

    my $pubkey = $privkey->public_key;

=head1 DESCRIPTION

This module implements digital signing algorithm (DSA) on elliptic curves (EC).

There are two classes:

* EC::DSA::PublicKey derives from EC::Point and is basically the public point
of the key pair.  This class only adds a 'verify' method.

* EC::DSA::PrivateKey derives from Math::BigInt and is the secret exponant.
This class only adds a 'sign' method.

=head1 SEE ALSO

EC, EC::Curves

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
