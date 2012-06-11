use strict;
use warnings;
use bigint;

package EC::DSA;
require EC;

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
