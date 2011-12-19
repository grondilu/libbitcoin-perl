#!/usr/bin/perl -w
# Satoshi Nakamoto's encoding in Perl.
package Bitcoin::Base58;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(encode decode);

use strict;
use warnings;

use bigint;

use Bitcoin qw(BASE58);

my %b58; $b58{(BASE58)[$_]} = $_ for 0 .. 57;

sub decode { shift =~ m/.$/p ? $b58{${^MATCH}} + 58*decode(${^PREMATCH}) : 0 }
sub encode { my $x = shift; return encode($x/58) . (BASE58)[$x%58] if $x > 0 } 

1;

__END__

=head1 TITLE

Bitcoin::Base58

=head1 SYNOPSIS

    use Bitcoin::Base58 qw(encode decode);

    print decode 'z';  # 57
    print decode '211';  # 58*58 = 3364
    my $i = rand(1000);
    decode(encode $i) == $i;   # True

=head1 DESCRIPTION

This module implements Satoshi Nakamoto's Base58 encoding.

It DOES NOT implement checksum or version padding that is present in a bitcoin
address.  To do this, use the Bitcoin::Address module.

=head1 BUGS

Probably none, at least with Perl 5.14

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

