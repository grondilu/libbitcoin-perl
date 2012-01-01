#!/usr/bin/perl -w
package Bitcoin;
@ISA = qw(Exporter);
@EXPORT_OK = qw(BASE58 BTC);

use constant BTC =>  "\x{0243}";  # Ƀ
use constant BASE58	=> qw{
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
};

use constant {
    # more boring stuff
    MAX_BLOCK_SIZE	=>   1_000_000,
    COIN		=> 100_000_000,
    CENT		=>   1_000_000,
    MAX_MONEY		=>       21e14,
    TEST		=>           0,
};

sub hash160 {
    return qx/
    perl -e 'print pack q(b*), "@{[unpack 'b*', shift]}"' |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary
    /;
}

sub hash {
    use Digest::SHA qw(sha256);
    sha256 sha256 shift;
}

1;

__END__
static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
static const int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
static const int64 COIN = 100000000;
static const int64 CENT = 1000000;
static const int64 MIN_TX_FEE = 50000;
static const int64 MIN_RELAY_TX_FEE = 10000;
static const int64 MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(int64 nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
static const int COINBASE_MATURITY = 100;
#ifdef USE_UPNP
#static const int fHaveUPnP = true;
##else
#static const int fHaveUPnP = false;
##endif
#

=head1 TITLE

Bitcoin

=head1 SYNOPSIS

    use Bitcoin qw(BASE58 BTC);

    printf "In a bitcoin address, authorized characters are: %s\n", join(', ', BASE58);
    printf "You owe me %.2f%s.\n", 10, BTC;

=head1 DESCRIPTION

Bitcoin is a peer-to-peer electronic cash system created in 2009 by Satoshi Nakamoto.  This module
and its submodules implement several tools for bitcoin-related operations.

This particular module implements bitcoin's specific constants and functions
that didn't fit in any subcategories.

=encoding utf8

It currently contains:

=over

=item * the Ƀ character, defined as the C<BTC> constant ;

=item * the base-58 charset (C<BASE58> list constant);

=item * hash functions such as C<hash160> which is actually a SHA-256 followed by a RIPEMD-160 ;

=back

The BASE58 constant has been put here instead of in Bitcoin::Base58 because
Bitcoin::Base58::BASE58 would have been kind of redundant.

Only BASE58 and BTC can be exported.

=head1 SUBMODULES

The Bitcoin module is not supposed to contain much.  Most useful stuffs are
implemented in submodules.

This section just sumarize their fonctionalities.  See their POD for details.

=head2 Bitcoin::Address

This class encapsulates a bitcoin address and allows checksum validation, version
or format conversion.

=head2 Bitcoin::PrivateKey

This class inherits from C<Bitcoin::Address> and encapsulates a bitcoin private key.

Its default version number is 128 instead of 0, as expected in the Wallet Import Format
that can be obtained with the C<toWIF> method.

Encryption is also supported using C<Crypt::Rijndael>.

=head2 Bitcoin::Wallet

This class implements a tie mechanism to store bitcoin private keys.  It 
provides transparent entry validation and encryption in a Berkeley database.

    tie my %wallet, 'Bitcoin::Wallet', '/path/to/my/wallet';
    $wallet{$addr} = $key;

It DOES NOT allow reading/writing a bitcoin wallet file as used in the official
bitcoin client.  

=head2 Bitcoin::Electrum

Electrum is a bitcoin lightweight client/server architecture originally written
in Python.  Hopefully someday this module will be a Perl implementation of Electrum.

=head1 SEE ALSO

Bitcoin::Address, Bitcoin::PrivateKey, Bitcoin::Base58, EC, EC::DSA

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

