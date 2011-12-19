#!/usr/bin/perl -w
package Bitcoin;
@ISA = qw(Exporter);
@EXPORT_OK = qw(BASE58 BTC hash hash160);

use constant BTC	=> "\x{0243}";  # Ƀ
use constant BASE58	=> qw(
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
);

sub hash160 {
    my $_ = unpack 'H*', shift;
    return qx/
    perl -e 'print pack q(H*), "$_"' |
    openssl dgst -sha256 -binary |
    openssl dgst -rmd160 -binary
    /;
}

use Digest::SHA qw(sha256);
sub hash { sha256 sha256 shift }



1;

__END__

=head1 TITLE

Bitcoin

=head1 SYNOPSIS

    use Bitcoin qw(BASE58 BTC);

    print  "In a bitcoin address, authorized characters are:", join(', ', BASE58), ".\n";
    printf "you owe me %.2f%s\n", 10, BTC;

    use Bitcoin::Address;

    my $addr = '1DxH3bjYeCKbSKvVEsXQUBjsTcxagmWjHy';
    eval { new Bitcoin::Address $addr };
    die "your address is not valid!" if $@;

    use Bitcoin::PrivateKey;
    my $key = new Bitcoin::PrivateKey;

    printf "please send me %.2f%s to this bitcoin address: %s\n", 10, BTC, $key->address;

=head1 DESCRIPTION

This module implements bitcoin's specific constants and functions that didn't
fit in any subcategories.

=encoding utf8

It currently contains:

=over

=item * the Ƀ character, defined as the C<BTC> constant ;

=item * the base-58 charset (C<BASE58> list constant);

=item * hash functions such as C<hash160> which is actually a SHA-256 followed by a RIPEMD-160 ;

=back

The BASE58 constant has been put here instead of in Bitcoin::Base58 because
Bitcoin::Base58::BASE58 would have been kind of redundant.

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

=head1 SEE ALSO

Bitcoin::Address, Bitcoin::PrivateKey, Bitcoin::Base58

=cut

