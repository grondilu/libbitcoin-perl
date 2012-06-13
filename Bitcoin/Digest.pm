#!/usr/bin/perl
use strict;
use warnings;

package Bitcoin::Digest;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(
hash256_bin hash256_hex hash256_int hash160_bin hash160_hex hash160_int
);

# Declarations
sub hash256_bin; sub hash256_hex; sub hash256_int; 
sub hash160_bin; sub hash160_hex; sub hash160_int;

# Definitions
sub hash256_bin { use Digest::SHA qw(sha256); sha256 sha256 shift }
sub hash160_bin {
    scalar qx/
    perl -e 'print pack q(b*), "@{[unpack 'b*', shift]}"' |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary
    /;
}

sub hash160_hex { unpack 'H*', reverse hash160_bin shift }
sub hash256_hex { unpack 'H*', reverse hash256_bin shift }

{
    use bigint;
    sub hash160_int { hex unpack 'H*', hash160_hex shift }
    sub hash256_int { hex unpack 'H*', hash256_hex shift }
}


1;
