#!/usr/bin/perl
package Bitcoin::Key;
use strict;
use warnings;
use Bitcoin;
use Bitcoin::Util;
use Bitcoin::Address;

# EC Settings
use EC qw(secp256k1);

package Bitcoin::Key::Master;
our @ISA = qw(Bitcoin::Key::Secret);
use overload
'&' => sub {
    return $_[1] & $_[0] if $_[2];
    new Bitcoin::Key::Secret +(Bitcoin::hash_int($_[1]) + $_[0]->value) % $EC::G->[2];
},
'<<' => sub {
    return $_[0] >> $_[1] if $_[2];
    if    (ref $_[1] ne '')            {...}
    elsif ($_[1] =~ /\A\d+\Z/)         { $_[0] << Bitcoin::Util::itob $_[1] }
    else  { new Bitcoin::Key::Secret join '', map $_[0]->twofish->encrypt(pack 'a16', $_), $_[1] =~ /(.{1,16})/gms }
},
'>>' => sub {
    return $_[1] << $_[0] if $_[2];
    if    (ref $_[1] ne 'Bitcoin::Key::Secret') {...}
    else { join '', map { $_[0]->twofish->decrypt($_) =~ s/\x{00}+\Z//r } $_[1]->data =~ /(.{16})/gms }
},
;

sub twofish {
    use Crypt::Twofish;
    my $_ = shift->_no_class;
    return new Crypt::Twofish pack 'a32', $_->data;
}

package Bitcoin::Key::Private;
our @ISA = qw(Bitcoin::Key::Secret);
package Bitcoin::Key::Secret;
require Bitcoin::Base58;
our @ISA = qw(Bitcoin::Base58::Data);

use overload '&{}' => sub {
    my $this = shift;
    sub { $this->sign(@_) }
};
    
# Redefined methods
sub size() { 256 }
sub default_version() { Bitcoin::TEST ? 129 : 128 }

# aliases
{
    no warnings 'once';
    *toWIF = *WIF = \&toBase58;
}

# Additional methods
sub encrypt;
sub decrypt;
sub address;
sub public_point;
sub cipher;
sub salt;
sub sign;
sub prompt;

# additional operator overloading
use overload
'+' => sub {
    my ($a, $b) = @_;
    warn 'operands are not blessed into the same package' unless ref $a eq ref $b;
    ref($a)->new( ($a->value + $b->value) % $EC::G->[2] )
},
'*' => sub {
    if ($_[2] or ref $_[1] ne 'EC::Point') {
	my ($a, $b) = @_;
	warn 'operands are not blessed into the same package' unless ref $a eq ref $b;
	ref($a)->new(($b->value * $a->value) % $EC::G->[2]);
    }
    else { EC::mult $_[0]->value, $_[1] }
},
'int' => sub { shift->value },
'exp' => sub { shift->public_point },
;


# definitions
#
sub new {
    my $class = shift->_no_instance;
    my $arg = shift;
    my $version = shift;
    if    (not defined $arg)                 { new $class Bitcoin::Util::randInt }
    elsif ($arg eq '')                       {...}
    elsif (ref $arg eq 'Crypt::Rijndael')    { (new $class)->encrypt($arg) }
    elsif ($arg =~ m/-+BEGIN [^-]* KEY---/)  { new $class $class->_from_PEM($arg), $version }
    else                                     { SUPER::new $class $arg, $version }
}

sub value {
    my $value = shift->SUPER::value;
    die "secret key is encrypted" unless ref $value eq 'Math::BigInt';
    return $value;
}

sub encrypt {
    my $_ = shift->_no_class;
    # noise filling -> encrypt
    $$_[0] .= '__STOP__'; $$_[0] .= chr rand 256 while 8*length($$_[0]) % 128;
    $$_[0] = ref->cipher(shift)->encrypt($$_[0]);
    return $_;
}

sub decrypt {
    my $_ = shift->_no_class;
    # decrypt -> remove noise
    $$_[0] = ref->cipher(shift)->decrypt($$_[0]);
    die 'wrong password' unless $$_[0] =~ s/__STOP__.*//ms;
    use Math::BigInt; $$_[0] = new Math::BigInt $$_[0];
    return $_;
}

sub public_point { EC::mult shift->_no_class->value, $EC::G }
sub public_key   { new EC::DSA::PublicKey $EC::G, shift->public_point }
sub address      { new Bitcoin::Address $_[0]->public_point, $_[1] }

sub _from_PEM {
    my $_ = shift->_no_instance;
    return pack 'H*', qx(
    echo "@{[shift]}" |
    openssl ec -text -noout 2>&- |
    sed -n '3,5s/[: ]//gp'
    ) =~ s/\n//gr;
}

sub cipher {
    use Digest::SHA qw(sha256);
    shift; # ignoring calling object
    my $arg = shift;
    if (ref($arg) eq 'Crypt::Rijndael') { $arg }
    else {
	use Crypt::Rijndael;
	Crypt::Rijndael->new(sha256($arg || Bitcoin::DUMMY_PASSWD), Crypt::Rijndael::MODE_CBC);
    }
}

sub sign {
    my $_ = shift->_no_class;
    my $key = new EC::DSA::PrivateKey $EC::G, $_->value;
    $key->sign(Bitcoin::hash_int shift);
}

sub prompt {
    my $class = shift->_no_instance;
    system "stty -echo";
    print "Enter your key in WIF: ";
    my $WIF = <STDIN>; chomp $WIF;
    print "\n";
    system "stty echo";
    $class->new($WIF);
}

1;

__END__
=head1 TITLE

Bitcoin::Key, Bitcoin::Key::Secret

=head1 SYNOPSIS

    use Bitcoin::Key;

    my $key = new Bitcoin::Key::Secret;
    my $key = new Bitcoin::Key::Secret '5JZDTbbezKW7dZSPECIMENSPECIMENSPECIMENxxeMZnZvev8Dy';
    my $key = new Bitcoin::Key::Secret 123456789;
    my $key = new Bitcoin::Key::Secret <<'stop' ;
    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIGF5sspCOHUUAGf4C1SPECIMENSPECIMENSPECIMENSjoAcGBSuBBAAK
    oUQDQgAEg/kE+E72DbBSPECIMENSPECIMENSPECIMENEz1/JZ00Qt3wJQQwUC0W9
    7INs0AnqUgxwMyO5JL1TKOf1vP0Zbw==
    -----END EC PRIVATE KEY-----
    stop
    print $key;
    print $key->address;
    my $secexp = $key->value;
    my $secexp = int $key;
    my $public_point = $key->public_point;
    my $public_point = exp $key;

    my $master_key = new Bitcoin::Key::Master;
    my $sub_key = $master_key << 'ASCII account name';
    my $account_name = $master_key >> $sub_key;

    $encrypted_key = $ey->encrypt('dummy password');
    $decrypted_key = $encrypted_key->decrypt('dummy password');

    print $key1 + $key2;
    print $key1 * $key2;
    print $key * bless [ $x, $y ], 'EC::Point';

=head1 DESCRIPTION

This class encapsulates a bitcoin private key, with possible encryption and
random generation.

It inherits from C<Bitcoin::Address> as it shares with it the version-checksum encoding
system (called "Wallet Import Format" [WIF] for a private key).

=head2 Key generation

The key can be generated in several ways.

=head3 Random generation

The most basic use of the class consists in generating a random key by calling
the constructor with no argument:

    my $key = new Bitcoin::Key::Secret;

In this case, the constructor creates, as randomly as possible, a 32-bytes
integer and uses it as secret exponent of the secp256k1 elliptic curve.

=head3 Generation from WIF or PEM

This duplicates a key from a WIF or PEM representation.  It can be usefull for
recovery, import, or checksum validation. 

    my $key = new Bitcoin::Key::Secret '5JZDTbbezKW7dZcfo5auX8koqGzcJV5kA7MiehxxeMZnZvev8Dy';
or
    my $key = new Bitcoin::Key::Secret <<'...' ;
    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIInGGXtUw/SrnANninoVGzc4S6cLGIVIqUKSGTHas9afoAcGBSuBBAAK
    oUQDQgAEREF8RQPfTBofCdiKvyOaS1PnxwJx+x+UWp2f4B9SkvNDGYyRRgiMTPr4
    o+BZJ/optSdvTNb0WvZeuTQ+BVm+TA==
    -----END EC PRIVATE KEY-----
    ...

=head3 Generation from an integer

This way of creating a key was designed for internal use but is allowed for end user too.

It consists of giving the constructor an instance of Math::BigInt.  Such an
integer will be directly used as the secret exponent.

    use bigint;
    my $key = new Bitcoin::Key::Secret  256**16 + 1;

=head3 Deriving from a master key using ASCII account names

It is possible to derive an infinite number of keys from a master key using ASCII string
to differentiate them.  See L<Master keys> below.

=head2 AES Encryption

The C<encrypt> and C<decrypt> methods do in-place encryption and decryption.  Both
return the reference of the modified calling object.

Argument can be either a password or a previously built C<Crypt::Rijndael> cipher.

    use Crypt::Rijndael;
    my $cipher = new Crypt::Rijndael "some password";
    my $key = Bitcoin::Key::Secret->new->encrypt($cipher);

It is also possible to provide the cipher as an argument to the constuctor:

    my $key = new Bitcoin::Key::Secret $cipher;

Once a key is encrypted, most method calls will die with a "key is encrypted"
message.  Basically only the C<decrypt> method can be executed.

=head2 Overloaded operators

Several operators have been overloaded for this class in order to ease elliptic
curve related calculations.   Addition or multiplication of two keys returns a
key whose value is the modular sum or multiplication of the keys values.
Multiplicating a key with a C<'EC::Point'>-blessed reference, in that order,
returns the elliptic curve multiplication of the point by the key value.

=head2 Master keys

The class Bitcoin::Key::Master inherits from Bitcoin::Key::Secret and overloads
'<<' and '>>' opperators.  This allows creation of I<subkeys> from
32-bytes-longed identifier strings.  Any longer string will be truncated.

    my $master_key = new Bitcoin::Key::Master;
    my $subkey = $master_key << 'some string';

The processus is not entirely destructive, so it is possible to retrieve the
original string from the subkey, or at least the first 32 bytes.

    my $account_name = $master_key >> $subkey;

   
=head2 Message signing

Derefencing a key as a subroutine will perform EC::DSA signature on a
Bitcoin::hash digest.  The result is a C<$r, $s> integer pair.  Use Crypt::ASN1
if you need an ASN1 encoding. 

    my @sig = $key->('message to be signed');

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
