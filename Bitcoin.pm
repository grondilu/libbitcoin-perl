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
   '0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d' =>  11111,
   '000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6' =>  33333,
   '00000000001e1b4903550a0b96e9a9405c8a95f387162e4944e8d9fbe501cd6a' =>  68555,
   '00000000006a49b14bcf27462068f1264c961f11fa2e0eddd2be0791e1d4124a' =>  70567,
   '0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20' =>  74000,
   '00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97' => 105000,
   '000000000000774a7f8a7a12dc906ddb9e17e75d684f15e00f8767f9e8f36553' => 118000,
   '00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe' => 134444,
   '000000000000033b512028abb90e1626d8b346fd0ed598ac0a3c371138dce2bd' => 140700,
};

sub hash160 {
    scalar qx/
    perl -e 'print pack q(b*), "@{[unpack 'b*', shift]}"' |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary
    /;
}
sub hash160_hex { unpack 'H*', hash160 @_ }

sub hash;
sub hash_hex;
sub hash_int;
{
    use Digest::SHA qw(sha256);
    sub hash     { sha256 sha256 shift }
    sub hash_hex { unpack 'H*', reverse hash shift }
    sub hash_int { use bigint; hex unpack 'H*', hash shift }
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

=item * The genesis hash code;

=item * the blockchain checkpoints;

=back

The BASE58 constant has been put here instead of in Bitcoin::Base58 because
Bitcoin::Base58::BASE58 would have been kind of redundant.

Only BASE58 and BTC can be exported.

=head1 SUBMODULES

The Bitcoin module is not supposed to contain much.  Most useful stuffs are
implemented in submodules.

This section just sumarize their fonctionalities, and several other modules
exist but are not documented here yet.  See their POD in the source code tree.

=head2 Bitcoin::Database

This class inherits from BerkeleyDB::Btree and provides default environnement
for opening a bitcoin database used by the vanilla client.

=head2 Bitcoin::Base58

This module implements Satoshi's base58 encoding.  It also contains an abstract class
implementing version and checksum coding used for Bitcoin addresses and private keys.
See Bitcoin::Address and Bitcoin::Key::Secret.

=head2 Bitcoin::Electrum

Electrum is a bitcoin lightweight client/server architecture originally written
in Python.  Hopefully someday this module will be a Perl implementation of Electrum.

=head1 SEE ALSO

Bitcoin::CNames, Bitcoin::Address, Bitcoin::Block, Bitcoin::Transaction, Bitcoin::Base58, EC

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 CREDITS

Most of this code is inspired from Gavin Andersen's bitcointools, ThomasV's
Electrum project, and of course from Satoshi Nakamoto's reference
implementation in C++.

Many, many thanks to Satoshi for what he accomplished.

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

