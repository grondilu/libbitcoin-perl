#!/usr/bin/perl -w
package Bitcoin::Address;
use strict;
use warnings;
use integer;
use bigint try => 'GMP';

use Bitcoin;
use Bitcoin::Base58 qw(encode decode);
use Digest::SHA qw(sha256);

sub new {
    my $class = shift;
    die "instance method call not implemented" if ref $class;
    my $_ = shift;
    my $version = shift || $class->version;
    if (ref eq 'Math::BigInt') {
        $_ += $version * 2**$class->size;
	$_ = $_*256**4 + $class->checksum($_);
	return bless \(($version ? '' : '1'). encode $_), $class;
    }
    elsif (ref eq 'EC::DSA::PublicKey') {
	...
    }
    elsif (ref eq $class) {
	my $copy = new $class $_->value, $_->version;
	die "wrong checksum" if $copy->checksum != $_->checksum;
	return $version eq $_->version ? $copy : new $class $_->value, $version;
    }
    elsif (m/^[@{[Bitcoin::BASE58]}]+$/i)		{ new $class bless(\$_, $class), $version }
    elsif (m,^(?:0x)?[0-9A-F]{@{[$class->size/4]}}$,i)	{ new $class hex($_), $version }
    elsif (m/-+BEGIN [^-]* KEY---/)			{ new $class $class->_hash_from_PEM($_), $version }
    else						{ die "wrong argument format ($_)" }
}

sub size { 160 }
sub default_version { 0 }

sub version {
    my $_ = shift;
    return ref($_) ? decode($$_) / 256**4 / 2**$_->size : $_->default_version;
}

sub value {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    return decode($$_) / 256**4 % 2**$_->size;
}

sub checksum {
    my $_ = shift;
    return decode($$_) % 256**4 if ref;
    return hex unpack 'H8', sha256 sha256
	pack 'H*', ((0x100*2**$_->size + shift)->as_hex =~ s/0x1//r);
}

sub _hash_from_PEM {
    my $_ = shift;
    die "instance method call not implemented" if ref;
    return unpack 'H40', qx/
    echo "@{[shift]}" |
    openssl ec -pubin -pubout -outform DER 2>&- |
    tail -c 65 |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary
    /;

}

sub toBase58 {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    return $_->version == 0 && $$_ !~ /^1/ ? "1$$_" : $$_;
}

sub toHex {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    return +(256**4 * 2**$_->size * 0x100 + decode $$_)->as_hex =~ s/0x1//r;
}

1;


__END__

=head1 TITLE

Bitcoin::Address

=head1 SYNOPSIS

    use Bitcoin::Address;

    # basic instanciation
    my $addr = Bitcoin::Address->new('1DxH3bjYeCKbSKvVEsXQUBjsTcxagmWjHy');
    my $addr = new Bitcoin::Address '1DxH3bjYeCKbSKvVEsXQUBjsTcxagmWjHy';

    # simple blessing  (but no checksum verification)
    my $addr = '1DxH3bjYeCKbSKvVEsXQUBjsTcxagmWjHy'
    bless \$addr, 'Bitcoin::Address';
    my $version = (\$addr)->version;
    

    # conversion to Hex is always 40 nibbles long, with no leading '0x'
    print $addr->toHex;		# prints 008e15c7e4ca858c3f412461bee5d472b0b6c362a5b6673b28

    # changing version number
    $addr = Bitcoin::Address->new($addr, 1);
    print $addr->version;  # prints 1
    print $$addr;          # prints dHt2i2qMNnUFm4aGHrixK1f68DXLyjq4L

    # instanciation from a PEM public key
    $addr = Bitcoin::Address->new(<<EOF
    -----BEGIN PUBLIC KEY-----
    MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEg/kE+E72DbB6yuHh8ge1FperHOHDahjP
    zuXEz1/JZ00Qt3wJQQwUC0W97INs0AnqUgxwMyO5JL1TKOf1vP0Zbw==
    -----END PUBLIC KEY-----
    EOF
    );
   

=head1 DESCRIPTION

This class encapsulates a bitcoin address, and allows conversion to
hexadecimal.

It can be instanciated from a bitcoin address in base58, from a hash160 in
hexadecimal, from a Math::BigInt instance, or from a public key in PEM format.

Instanciation fails if format or checksum is incorrect.

An instance is a blessed reference to the base58 string, so
C<< $addr->toBase58() >> is almost the same as C<$$addr>.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
