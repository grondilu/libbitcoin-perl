#!/usr/bin/perl -w
package Bitcoin;
@ISA = qw(Exporter);
@EXPORT_OK = qw(BASE58 BTC);
use v5.14;

use constant BASE58	=> qw{
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
};
use constant TEST	=> 0;

use constant {
    BTC                 =>  "\x{0243}",  # Ƀ
    GENESIS             => !TEST ?  '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f' : '00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008',
    TIMES20090103       => 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',

    DATA_DIR		=> $ENV{HOME}.'/.bitcoin',

    PROOF_OF_WORK_LIMIT =>          32, # bits
    MAX_BLOCK_SIZE	=>   1_000_000,
    COIN		=> 100_000_000,
    CENT		=>   1_000_000,
    MAX_MONEY		=>       21e14,

    DEFAULT_PORT	=>        8333,

    IRC			=> [ 'irc.lfnet.org:6667', '#bitcoin'. (TEST ? 'TEST' : '') ],

    DUMMY_PASSWD        => 'dummy password',
};

use constant CREDITS	=>  'Satoshi Nakamoto', 'Gavin Andersen', 'bitcoin developpers';

sub hash160 {
    return scalar qx/
    perl -e 'print pack q(b*), "@{[unpack 'b*', shift]}"' |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary
    /;
}
sub hash160_hex { return unpack 'H*', hash160 @_ }

sub hash;
sub hash_hex;
{
    use Digest::SHA qw(sha256);
    sub hash     { sha256 sha256 shift }
    sub hash_hex { unpack 'H*', reverse hash shift }
}

1;

__END__

=head1 TITLE

Bitcoin

=head1 SYNOPSIS

    use Bitcoin qw(BASE58 BTC);

    printf "In a bitcoin address, authorized characters are: %s\n", join(', ', BASE58);
    printf "You owe me %.2f%s.\n", 10, BTC;

=head1 DESCRIPTION

Bitcoin is a peer-to-peer electronic cash system created in 2009 by Satoshi Nakamoto.  This module
and its submodules implement several tools for bitcoin-related operations.  This is part of a project aiming
at a full Perl implementation of the bitcoin protocol.

This particular module implements bitcoin's specific constants and functions
that didn't fit in any subcategories.

=encoding utf8

It currently contains:

=over

=item * the Ƀ character, defined as the C<BTC> constant ;

=item * the base-58 charset (C<BASE58> list constant);

=item * hash functions such as C<hash160> which is actually a SHA-256 followed by a RIPEMD-160 ;

=item * The genesis hash code

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

=head1 CREDITS

Most of this code is inspired from Gavin Andersen's bitcointools, ThomasV's
Electrum project, and of course from Satoshi Nakamoto's reference
implementation in C++.

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

