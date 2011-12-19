#!/usr/bin/perl
package Bitcoin::PrivateKey;
use Bitcoin::Address;
use Digest::SHA qw(sha256);
@ISA = qw(Bitcoin::Address);

use strict;
use warnings;

use Crypt::Rijndael;
use constant DUMMY_PASSWD => 'dummy password';

sub size { 256 }
sub default_version { 128 }

use EC;
use EC::Curves qw(secp256k1);
($EC::p, $EC::a, $EC::b) = map secp256k1->{$_}, qw( p a b );
my $G = secp256k1->{G};

our $entropy = 256;	# entropy in bits

sub new {
    my $class = shift;
    if (not @_) { return $class->new( -entropy => $entropy ) }
    elsif ($_[0] =~ /^-/) {
	my %arg = @_;
	if (exists $arg{'-entropy'}) {
	    use bigint;
	    use Digest::SHA qw(sha256_hex);
	    my $r = hex sha256_hex time . $$ . qx(openssl rand -rand $0 32 2>&-) . qx(ps axww |gzip -f);
	    return $class->SUPER::new($r % 2**$arg{'-entropy'});
	}
	else { ... }
    }
    elsif (@_ > 2) { use LongBase; return $class->SUPER::new(LongBase::decode @_) }
    else { return $class->SUPER::new($_[0]) }
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

sub toWIF {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    return $_->toBase58;
}

sub encrypt {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    my $passwd = sha256(shift || DUMMY_PASSWD);
    # noise filling -> encrypt
    $$_ .= '______'; $$_ .= chr rand 256 while length $$_ < 128;
    $$_ = (new Crypt::Rijndael $passwd, Crypt::Rijndael::MODE_CBC)->encrypt($$_);
}

sub decrypt {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    my $passwd = sha256(shift || DUMMY_PASSWD);
    # decrypt -> remove noise
    $$_ = (new Crypt::Rijndael $passwd, Crypt::Rijndael::MODE_CBC)->decrypt($$_);
    $$_ =~ s/______.*//ms;
    return $_;
}

sub address {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    use Bitcoin qw(hash160);
    use EC;
    use bigint;
    my $point = EC::mult $_->value, $G;
    my $h = unpack 'H*', hash160 chr(4) . pack 'H*', join '', map +($_+2**256)->as_hex =~ s/0x1//r, @$point;
    Bitcoin::Address->new($h)->toBase58;
}

sub mnemonic {
    use LongBase;
    return LongBase::encode shift->value;
}

1;

__END__
=head1 TITLE

Bitcoin::PrivateKey

=head1 SYNOPSIS

    use Bitcoin::PrivateKey;

    # create a key from Wallet Import Format or PEM
    my $key = Bitcoin::PrivateKey->new('5JZDTbbezKW7dZcfo5auX8koqGzcJV5kA7MiehxxeMZnZvev8Dy');
    print $key->address;   # should print 15gR9zUv3YW6DRf9fVvPXC7x9csPM8QcTg
    my $key = new Bitcoin::PrivateKey <<EOF
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

    # create a new, random key (default is 256 bits entropy)
    my $randomkey = new Bitcoin::PrivateKey;
    print $$randomkey;

    # create a privatekey with 128 bits entropy
    my $littlekey = new Bitcoin::PrivateKey -entropy => 128;
    print $littlekey->mnemonic;

    # set a 128 bit entropy for all new keys from now on
    $Bitcoin::PrivateKey::entropy = 128;

    # The encrypt method returns a plain encrypted string, not the encrypted object.
    my $encrypted_key = $key->encrypt('dummy password');

    # To recover a key from its encrypted string, you must bless it first.
    my $decrypted_key = bless(\$encrypted_key, 'Bitcoin::PrivateKey')->decrypt('dummy password');

=head1 DESCRIPTION

This class derives from Bitcoin::Address and implements a few additional
functionalities such as random generation and encryption.

This class DOES NOT perform message signatures.  Use EC::DSA::PrivateKey to do this.

=head2 Random generation

The most basic use of the class consists in generating a random key by calling
the constructor with no argument:

    my $key = new Bitcoin::PrivateKey;

The returned scalar is a reference to the key in WIF format.  Thus, to print
this key in such format, you can just write:

    print $$key;

You can also use the C<toWIF> or C<toBase58> method (the same method with two different names).

    print $key->toWIF;

It is also possible to chose the maximal amount of entropy in your key.  By doing so the method assumes you want
to memorize the key, so it will give you the mnemonic representation of the key:

    my ($key, @mnemonic) = new Bitcoin::PrivateKey -entropy => 128;

=head2 Validation and format conversion

You can instanciate a key from its WIF string:

    my $key = new Bitcoin::PrivateKey '5JZDTbbezKW7dZcfo5auX8koqGzcJV5kA7MiehxxeMZnZvev8Dy';

or from a PEM format:

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

Afterwards you can get the corresponding bitcoin address with the C<address> method:

    print $key->address;

=head2 AES Encryption

The C<encrypt> method does in-place encryption and returns the non-blessed
encrypted string.  The C<decrypt> method does in-place decryption and returns the
calling instance.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
