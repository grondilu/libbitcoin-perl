#!/usr/bin/perl -w
package Bitcoin::Address;
require Bitcoin::Base58;
@ISA = qw(Bitcoin::Base58::Data);
use strict;
use warnings;

use Bitcoin;

# redefined public methods
sub size() { 160 }
sub default_version() { Bitcoin::TEST ? 1 : 0 }

# additional public methods
;
# additional private methods
sub _from_PEM;
sub new {
    my $class = shift->_no_instance;
    my $arg = shift;
    my $version = shift;
    if (ref($arg) eq 'EC::DSA::PublicKey')   {...}
    if (ref($arg) eq 'EC::Point')            {
	use bigint;
	return new $class Bitcoin::hash160(
	    pack 'H2H64H64', '04', map +($_+2**256)->as_hex =~ s/0x1//r, @$arg[0,1]
	), $version;
    }
    elsif ($arg =~ m/---BEGIN [^-]* KEY---/)  { warn 'using PEM'; SUPER::new $class $class->_from_PEM($arg), $version }
    else	         		     { SUPER::new $class $arg, $version }
}

sub _from_PEM {
    my $_ = shift;
    die "instance method call not implemented" if ref;
    return scalar qx/
    echo "@{[shift]}" |
    openssl ec -pubin -pubout -outform DER 2>&- |
    tail -c 65 |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary 
    /;
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
