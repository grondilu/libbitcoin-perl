#!/usr/bin/perl -w
package Bitcoin::Wallet;
require DB_File;
@ISA = qw(DB_File);

use strict;
use warnings;

use DBM_Filter;
use Digest::SHA qw(sha256);

our $passwd;

sub TIEHASH {
    my $_ = shift;
    $passwd = shift || 'dummy passwd';
    my $obj = $_->SUPER::TIEHASH(@_);

    return $obj;
}


1;

__END__

=head1 TITLE

Bitcoin::Wallet

=head1 SYNOPSIS

    use Bitcoin::Wallet;

    my %wallet;
    system('stty -echo'); chomp( my $password = <STDIN> );
    tie %wallet, 'Bitcoin::Wallet', $password, '/path/to/my/wallet.bdb';
    ...
    untie %wallet;

=head1 DESCRIPTION

This module provides tie mechanism for a bitcoin wallet.

It has a simple publickey => privatekey structure, but it provides encryption
and prevents user from entering anything but valid keys in the database.

Other data such as transaction history, blocks or contacts should
be stored somewhere else.

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

