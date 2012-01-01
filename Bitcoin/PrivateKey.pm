#!/usr/bin/perl
package Bitcoin::PrivateKey;
require Bitcoin::Address;
require Exporter;
# A bitcoin privatekey inherits from a bitcoin address as it
# shares a common encoding system (Wallet Import Format)
@ISA = qw(Bitcoin::Address Exporter);
@EXPORT_OK = qw(G);

use strict;
use warnings;

use EC;
use EC::Curves qw(secp256k1);
EC::set_param secp256k1;

# group generator
use constant G => secp256k1->{G};

# default password for encryption
use constant DUMMY_PASSWD => 'dummy password';

# Redefined methods
sub new;
sub value;
sub size { 256 }
sub default_version { 128 }

# Additional methods
sub toWIF { shift->toBase58 }
sub encrypt;
sub decrypt;
sub randInt;
sub address;
sub public_point;
sub cipher;
sub salt;

# additional operator overloading
use overload
'+' => sub {
    my ($a, $b) = @_;
    warn 'operands are not blessed into the same package' unless ref $a eq ref $b;
    ref($a)->new( ($a->value + $b->value) % G->[2] )
},
'*' => sub {
    if ($_[2] or ref $_[1] ne 'EC::Point') {
	use bigint;
	($_[0]->value * $_[1]->value) % G->[2];
    }
    else { EC::mult $_[0]->value, $_[1] }
},
'int' => sub { shift->value },
'exp' => sub { shift->public_point },
;


# definitions
#
sub new {
    my $_ = shift;
    my $arg = shift;
    if (ref $arg eq 'Crypt::Rijndael') { $_->SUPER::new(randInt)->encrypt($arg) }
    else { $_->SUPER::new($arg // randInt()) }
}

sub value {
    my $value = shift->SUPER::value;
    die "key is encrypted" unless ref $value eq 'Math::BigInt';
    return $value;
}

sub encrypt {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    # noise filling -> encrypt
    $$_[1] .= '__STOP__'; $$_[1] .= chr rand 256 while 8*length($$_[1]) % 128;
    $$_[1] = ref->cipher(shift)->encrypt($$_[1]);
    return $_;
}

sub decrypt {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    # decrypt -> remove noise
    $$_[1] = ref->cipher(shift)->decrypt($$_[1]);
    die 'wrong password' unless $$_[1] =~ s/__STOP__.*//ms;
    use Math::BigInt; $$_[1] = new Math::BigInt $$_[1];
    return $_;
}

{
    use Digest::SHA qw(sha256 sha256_hex);

    sub cipher {
	shift; # ignoring calling object
	my $_ = shift;
	if (ref eq 'Crypt::Rijndael') { return $_ }
	else {
	    use Crypt::Rijndael;
	    return new Crypt::Rijndael sha256($_ || DUMMY_PASSWD), Crypt::Rijndael::MODE_CBC
	}
    }

    use bigint;

    sub randInt {
	shift; # ignoring calling object
	return hex sha256_hex time . $$ . qx(openssl rand -rand $0 32 2>&-) . qx(ps axww |gzip -f);
    }

    sub public_point {
	my $_ = shift;
	die "class method call not implemented" unless ref;
	return EC::mult $_->value, G;
    }

    sub address {
	my $_ = shift;
	die "class method call not implemented" unless ref;
	my $version = shift;
	return new Bitcoin::Address $_->public_point, $version;
    }

    sub _value_from_PEM {
	my $_ = shift;
	die "instance method call not implemented" if ref;
	return hex(qx(
	echo "@{[shift]}" |
	openssl ec -text -noout 2>&- |
	sed -n '3,5s/[: ]//gp'
	) =~ s/\n//gr);
    }

}


1;

__END__
=head1 TITLE

Bitcoin::PrivateKey

=head1 SYNOPSIS

    use Bitcoin::PrivateKey;

    my $key = new Bitcoin::PrivateKey;
    my $key = new Bitcoin::PrivateKey '5JZDTbbezKW7dZSPECIMENSPECIMENSPECIMENxxeMZnZvev8Dy';
    my $key = new Bitcoin::PrivateKey 123456789;
    my $key = new Bitcoin::PrivateKey <<EOF
    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIGF5sspCOHUUAGf4C1SPECIMENSPECIMENSPECIMENSjoAcGBSuBBAAK
    oUQDQgAEg/kE+E72DbBSPECIMENSPECIMENSPECIMENEz1/JZ00Qt3wJQQwUC0W9
    7INs0AnqUgxwMyO5JL1TKOf1vP0Zbw==
    -----END EC PRIVATE KEY-----
    EOF
    ;

    print $key;
    print $key->address;
    my $secexp = $key->value;
    my $secexp = int $key;
    my $public_point = $key->public_point;
    my $public_point = exp $key;

    $encrypted_key = $randomkey->encrypt('dummy password');
    $decrypted_key = $encrypted_key->decrypt('dummy password');

    print $key1 + $key2;


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

    my $key = new Bitcoin::PrivateKey;

In this case, the constructor creates, as randomly as possible, a 32-bytes
integer and uses it as secret exponent of the secp256k1 elliptic curve.

=head3 Generation from WIF or PEM

This duplicates a key from a WIF or PEM representation.  It can be usefull for
recovery, import, or checksum validation. 

    my $key = new Bitcoin::PrivateKey '5JZDTbbezKW7dZcfo5auX8koqGzcJV5kA7MiehxxeMZnZvev8Dy';

or

    my $key = new Bitcoin::PrivateKey <<EOF
    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIInGGXtUw/SrnANninoVGzc4S6cLGIVIqUKSGTHas9afoAcGBSuBBAAK
    oUQDQgAEREF8RQPfTBofCdiKvyOaS1PnxwJx+x+UWp2f4B9SkvNDGYyRRgiMTPr4
    o+BZJ/optSdvTNb0WvZeuTQ+BVm+TA==
    -----END EC PRIVATE KEY-----
    EOF

=head3 Generation from an integer

This way of creating a key was designed for internal use but is allowed for end user too.

It consists of giving the constructor an instance of Math::BigInt.  Such an
integer will be directly used as the secret exponent.

    use bigint;
    my $key = new Bitcoin::PrivateKey  256**16 + 1;

=head3 Salting a previous key

You can create a key by salting a previous one with any arbitrary string.  To
do so, the hash dereferenciation operator has been overloaded.Each fetched
value is a blessed reference to a new Bitcoin::PrivateKey object.

    my $main_key = new Bitcoin::PrivateKey;
    my %wallet = %$main_key;
    my $socks_key = $wallet{"savings account to buy alpaca socks"};
    print $socks_key->address;

Salting is deterministic, but also destructive: you can not retrieve the
salting string from the salted key.  Neither can you retrieve the main key.

If you create a whole wallet using this salting method, your main key becomes
highly sensitive information and should be properly encrypted and backed up.

=head2 AES Encryption

The C<encrypt> and C<decrypt> methods do in-place encryption and decryption.  Both
return the reference of the modified calling object.

Argument can be either a password or a previously built C<Crypt::Rijndael> cipher.

    use Crypt::Rijndael;
    my $cipher = new Crypt::Rijndael "some password";
    my $key = Bitcoin::PrivateKey->new->encrypt($cipher);

It is also possible to provide the cipher as an argument to the constuctor:

    my $key = new Bitcoin::PrivateKey $cipher;

Once a key is encrypted, most method calls will die with a "key is encrypted"
message.  Basically only the C<decrypt> method can be executed.

=head2 Overloaded operators

Several operators have been overloaded for this class in order to ease elliptic
curve related calculations.   Addition or multiplication of two keys returns a
key whose value is the modular sum or multiplication of the keys values.
Multiplicating a key with a C<'EC::Point'>-blessed reference, in that order,
returns the elliptic curve multiplication of the point by the key value.

=head2 Message signing

B<TODO>

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
