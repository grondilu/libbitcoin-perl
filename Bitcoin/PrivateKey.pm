#!/usr/bin/perl
package Bitcoin::PrivateKey;
require Bitcoin::Address;
# A bitcoin privatekey inherits from a bitcoin address as it
# shares a common encoding system (Wallet Import Format)
@ISA = qw(Bitcoin::Address);

use strict;
use warnings;

use EC;
use EC::Curves qw(secp256k1);
EC::set_param secp256k1;

# default password for encryption
use constant DUMMY_PASSWD => 'dummy password';

# Redefined methods
sub new;
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
    ref($a)->new( ($a->value + $b->value) % secp256k1->{G}[2] )
},
'<<' => sub {
    die "syntax error" if $_[2];
    my $_ = __PACKAGE__->new(shift);
    return $_->salt(shift);
};


# definitions
#
sub new {
    my $_ = shift;
    return $_->SUPER::new(shift // randInt());
}

sub _hash_from_PEM {
    my $_ = shift;
    die "instance method call not implemented" if ref;
    return qx(
    echo "@{[shift]}" |
    openssl ec -text -noout 2>&- |
    sed -n '3,5s/[: ]//gp'
    ) =~ s/\n//gr ;
}

sub encrypt {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    # noise filling -> encrypt
    $$_ .= '__STOP__'; $$_ .= chr rand 256 while length $$_ < 128;
    $$_ = ref->cipher(shift)->encrypt($$_);
}

sub decrypt {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    # decrypt -> remove noise
    $$_ = ref->cipher(shift)->decrypt($$_);
    use Bitcoin qw(BASE58);
    die "wrong password $$_" unless $$_ =~ /^[@{[BASE58]}]+__STOP__/x;
    $$_ =~ s/__STOP__.*//ms;
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

	return bless EC::mult($_->value, secp256k1->{G}), 'Point';
    }

    sub address {
	my $_ = shift;
	die "class method call not implemented" unless ref;
	my $version = shift;

	return new Bitcoin::Address $_->public_point, $version;
    }

    sub salt {
	my $_ = shift;
	die "class method call not implemented" unless ref;
	$_ = ref($_)->new(hex sha256_hex join ':', $_->toBase58, @_ );
	return $_;
    }

}


1;

__END__
=head1 TITLE

Bitcoin::PrivateKey

=head1 SYNOPSIS

    use Bitcoin::PrivateKey;

    $randomkey = new Bitcoin::PrivateKey;
    print $randomkey;

    $encrypted_key = $randomkey->encrypt('dummy password');
    $decrypted_key = bless(\$encrypted_key, 'Bitcoin::PrivateKey')->decrypt('dummy password');

    $key = Bitcoin::PrivateKey->new('5JZDTbbezKW7dZcfo5auX8koqGzcJV5kA7MiehxxeMZnZvev8Dy');
    print $key->address;
    $key = new Bitcoin::PrivateKey <<EOF
    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHQCAQEEIGF5sspCOHUUAGf4C151UAX3/8FG7dui5jOBflx86WSjoAcGBSuBBAAK
    oUQDQgAEg/kE+E72DbB6yuHh8ge1FperHOHDahjPzuXEz1/JZ00Qt3wJQQwUC0W9
    7INs0AnqUgxwMyO5JL1TKOf1vP0Zbw==
    -----END EC PRIVATE KEY-----
    EOF
    ;

    # building a secret exponent
    use Digest::SHA qw(sha256);
    my $secexp = "In cryptography we trust";
    $secexp = sha256 $secexp for 1 .. 1_000_000;
    use bigint;
    $secexp = hex unpack 'H*', $secexp;

    # create the private key from this secret exponent
    $key = new Bitcoin::PrivateKey $secexp;

    # adding two keys
    print $key + new Bitcoin::PrivateKey;


=head1 DESCRIPTION

This class encapsulates a bitcoin private key, with possible encryption and
random generation.

It inherits from C<Bitcoin::Address> as it shares with it the version-checksum encoding
system (called "Wallet Import Format" [WIF] for a private key).

This class DOES NOT perform message signatures.  Use EC::DSA::PrivateKey to do this.

=head2 Key generation

The key can be generated in several ways.

=head3 Random generation

The most basic use of the class consists in generating a random key by calling
the constructor with no argument:

    my $key = new Bitcoin::PrivateKey;

In this case, the constructor creates, as randomly as possible, a 32-bytes
integer and uses it as secret exponent of the secp256k1 elliptic curve.

This is the most secure way to generate a key, but there are very few
possibilities to allow the user to memorize such a key.  It has to be stored on
disk or paper.

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

You can create a key by salting a previous one with any arbitrary string.

    my $key = new Bitcoin::PrivateKey;
    salt $key "Long ago, in a distant land...";
    # - or -
    $key->salt("Long ago, in a distant land...");

Salting is deterministic, but also destructive: you can not retrieve the
salting string from the salted key.

This method does inplace modification and returns the modified calling object.  For creating
a new key without modifying the calling object, use the overloaded C<E<lt>E<lt>> operator:

    say $key << "Long ago, in a distant land...";

Beware: the C<salt> method accepts any number of strings as a arguments, but
the C<E<lt>E<lt>> operator only accepts one.

=head2 AES Encryption

The C<encrypt> method does in-place encryption and returns the non-blessed
encrypted string.  The C<decrypt> method does in-place decryption and returns the
calling instance.

Without argument, the function uses the seeding string if it exists, and dies
otherwise.

Encryption is mostly usefull for keys that were created using a random number.
For string-generated keys, it is probably safer not to store the key anywhere,
but to generate a single-use copy every time.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
