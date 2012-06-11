package EC::DSA::PublicKey;
use strict;
use warnings;
use overload '&{}' => sub { my $this = shift; sub { $this->verify(@_) } };

sub new {
    die "constructor's instance method call not implemented" if ref(my $class = shift);
    my ($generator, $point) = @_;
    die "generator should have an order" unless defined(my $n = $$generator[2]);
    die "bad order for generator" if EC::mult $n, $generator;
    bless [ map EC::check($_), $generator, $point ], $class;
}
sub verify {
    my $this = shift;
    die "class method call not implemented" unless ref $this;
    my $n = $this->[0][2];
    my ($h, $r, $s) = @_;
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
    my ($generator, $secret_multiplier) = @_;
    die "generator should have an order" unless defined(my $n = $$generator[2]);
    die "bad order for generator" if EC::mult $n, $generator;
    bless [ $generator, $secret_multiplier ], $class;
}
sub sign {
    use Bitcoin::Util;
    my $_ = shift;
    die "class method call not implemented" unless ref;
    my $generator = $_->[0];
    my $n = $generator->[2] // die 'unknown generator order';
    my $h = shift // die 'nothing to sign';
    my $random_k = shift // Bitcoin::Util::randInt;
    my $k = $random_k % $n;
    my $p = EC::mult $k, $generator;
    my $r = $$p[0];
    die "amazingly unlucky random number r" if $r == 0;
    my $s = ( NumberTheory::inverse_mod( $k, $n ) * ($h + ($$_[1] * $r) % $n) ) % $n;
    die "amazingly unlucky random number s" if $s == 0;
    return $r, $s;
}
sub public_key {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    new EC::DSA::PublicKey $_->[0], EC::mult $_->[1], $_->[0];
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
