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

=head1 DESCRIPTION

This module implements bitcoin's specific constants and functions that didn't
fit in any subcategories.

=encoding utf8

It currently contains:

=over

=item * the Ƀ character, defined as the 'BTC' constant ;

=item * the base-58 charset (BASE58 list constant);

=item * hash functions such as hash160 which is actually a SHA-256 followed by a RIPEMD-160 ;

=back

The BASE58 constant has been put here instead of in Bitcoin::Base58 because
Bitcoin::Base58::BASE58 would have been kind of redundant.

This module is not supposed to contain much.  Most useful stuffs are
implemented in submodules.

=head1 SEE ALSO

Bitcoin::Address, Bitcoin::PrivateKey, Bitcoin::Base58

=cut

