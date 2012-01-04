#!/usr/bin/perl -w
package Bitcoin::Address;
use strict;
use warnings;
use integer;

use Bitcoin;
use Bitcoin::Base58;
use Digest::SHA qw(sha256);

# package variables and constants
our $version;

# public methods
sub size;
sub default_version;
sub version;
sub value;
sub checksum;
sub toBase58;
sub toHex;

# private methods
sub _value_from_PEM;

sub size { 160 }
sub default_version { Bitcoin::TEST ? 1 : 0 }

use overload fallback => 'TRUE', q("") => sub { shift->toBase58 };

{
    use bigint;

    sub new {
	my $class = shift;
	die "instance method call not implemented" if ref $class;
	my $_ = shift;
	my $version = shift || $class->version;
	if (ref eq 'Math::BigInt') {
	    bless [ $version, $_ ], $class;
	}
	elsif (ref eq 'EC::DSA::PublicKey') {
	    ...
	}
	elsif (ref eq 'EC::Point') {
	    use EC;
	    use EC::Curves qw(secp256k1);
	    EC::set_param secp256k1;
	    EC::check $_;
	    return $class->new(
		hex(unpack 'H*',
		    Bitcoin::hash160 chr(4) .
		    pack 'H*', join '',
		    map +($_+2**256)->as_hex =~ s/0x1//r, @$_
		),
		$version)
	}
	elsif (ref eq $class) {
	    my $copy = new $class $_->value, $_->version;
	    die "wrong checksum" if $copy->checksum != $_->checksum;
	    return $version eq $_->version ? $copy : new $class $_->value, $version;
	}
	elsif (m/^[@{[Bitcoin::BASE58]}]+$/i)		{
	    my $_ = bless [
		map { $_ / 256**4 / 2**$class->size, $_ / 256**4 % 2**$class->size, $_ % 256**4 }
		Bitcoin::Base58::decode($_)
	    ], $class;
	    return new $class $_, $_->version;
	}
	elsif (m,^(?:0x)?[0-9A-F]{@{[$class->size/4]}}$,i)	{ new $class hex($_), $version }
	elsif (m/-+BEGIN [^-]* KEY---/)			{ new $class $class->_value_from_PEM($_), $version }
	else						{ die "wrong argument format" }
    }

    sub _value_from_PEM {
	my $_ = shift;
	die "instance method call not implemented" if ref;
	return hex unpack 'H40', qx/
	echo "@{[shift]}" |
	openssl ec -pubin -pubout -outform DER 2>&- |
	tail -c 65 |
	openssl dgst -sha256 -binary |
	openssl dgst -rmd160 -binary
	/;
    }

    sub checksum {
	my $_ = shift;
	return ref() ? $$_[2] // ref->checksum( $$_[0]*2**$_->size + $$_[1] ) :
	hex unpack 'H8', sha256 sha256 pack 'H*',
	((0x100*2**$_->size + shift)->as_hex =~ s/0x1//r);
    }

    sub toHex {
	my $_ = shift;
	die "class method call not implemented" unless ref;
	return +((2**$_->size * (0x100 + $_->version) + $_->value) * 256**4 + $_->checksum)->as_hex =~ s/0x1//r;
    }

    sub toBase58 {
	my $_ = shift;
	die "class method call not implemented" unless ref;
	return +($_->version > 0 ? '' : '1') . Bitcoin::Base58::encode hex $_->toHex;
    }

}

sub version {
    my $_ = shift;
    return ref($_) ? $$_[0] : $version // $_->default_version;
}

sub value {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    return $$_[1];
}

1;


__END__

=head1 TITLE

Bitcoin::Address

=head1 SYNOPSIS

    use Bitcoin::Address;

    # basic instanciation
    my $addr = new Bitcoin::Address '1DxH3bjYeCKbSKvVEsXQUBjsTcxagmWjHy';

    # conversion to Hex is always 40 nibbles long, with no leading '0x'
    print $addr->toHex;		# prints 008e15c7e4ca858c3f412461bee5d472b0b6c362a5b6673b28

    # changing version number
    $addr = new Bitcoin::Address $addr, 1;
    print $addr->version;  # prints 1
    print $addr;          # prints dHt2i2qMNnUFm4aGHrixK1f68DXLyjq4L

    # instanciation from a PEM public key
    $addr = new Bitcoin::Address <<stop ;
    -----BEGIN PUBLIC KEY-----
    MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEg/kE+E72DbB6yuHh8ge1FperHOHDahjP
    zuXEz1/JZ00Qt3wJQQwUC0W97INs0AnqUgxwMyO5JL1TKOf1vP0Zbw==
    -----END PUBLIC KEY-----
    stop
   

=head1 DESCRIPTION

This class encapsulates a bitcoin address, and allows conversion to
hexadecimal.

It can be instanciated from a bitcoin address in base58, from a hash160 in
hexadecimal, from a Math::BigInt instance, from a public key in PEM format or
from an elliptic curve public point.

Instanciation fails if format or checksum is incorrect.

The class overloads stringifcation, so a command such as C<say $addr;> should normaly 
print the bitcoin address as if it was a string.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
