#!/usr/bin/perl -w
package Bitcoin;
@ISA = qw(Exporter);
@EXPORT_OK = qw(BASE58 BTC);
use v5.14;

use constant TEST	=> 0;
use constant BASE58	=> qw{
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
};

use constant {
    BTC                 =>  "\x{0243}",  # Ƀ
    GENESIS             => !TEST ? '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f' : '00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008',
    TIMES20090103       => 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',

    DATA_DIR		=> $ENV{HOME}.'/.bitcoin',

    PROOF_OF_WORK_LIMIT =>          32, # bits
    MAX_BLOCK_SIZE	=>   1_000_000,
    COIN		=> 100_000_000,
    CENT		=>   1_000_000,
    MAX_MONEY		=>       21e14,

    DEFAULT_PORT	=>        8333,


    DUMMY_PASSWD        => 'dummy password',
};

use constant CREDITS	=> 'Satoshi Nakamoto', 'Gavin Andersen', 'bitcoin developpers';
use constant IRC	=> 'irc.lfnet.org', '6667', '#bitcoin'. (TEST ? 'TEST' : '');

use constant CHECKPOINTS => {
     11111 => "0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
     33333 => "0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
     68555 => "0x00000000001e1b4903550a0b96e9a9405c8a95f387162e4944e8d9fbe501cd6a",
     70567 => "0x00000000006a49b14bcf27462068f1264c961f11fa2e0eddd2be0791e1d4124a",
     74000 => "0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
    105000 => "0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
    118000 => "0x000000000000774a7f8a7a12dc906ddb9e17e75d684f15e00f8767f9e8f36553",
    134444 => "0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
    140700 => "0x000000000000033b512028abb90e1626d8b346fd0ed598ac0a3c371138dce2bd",
};

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

