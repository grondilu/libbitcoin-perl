#!/usr/bin/perl -w
use v5.14;
use strict;
use warnings;

package Bitcoin;
require EC::DSA;
use Bitcoin::Base58;

our $data_dir	= $ENV{BITCOIN_DATA_DIR} // $ENV{HOME}.'/.bitcoin';

package Bitcoin::Key;
require Bitcoin::Util;
our @ISA = qw( Bitcoin::Base58::Data    EC::DSA::PrivateKey );
sub size() { 256 }
sub version() { defined($ENV{BITCOIN_TEST}) ? 129 : 128 }
sub value { bless shift->copy(), 'Math::BigInt'; }

sub new {
    my $class = shift;
    my $arg = shift;
    if(not defined $arg) { return bless Bitcoin::Util::randInt(), $class }
    elsif(ref $arg ~~ [qw(Math::BigInt EC::DSA::PrivateKey)]) { bless $arg, $class }
    elsif($arg =~ m/\A$Bitcoin::Base58::b58+Z/i) {
	my $new = bless $class->value_from_address($arg), $class;
	die 'invalid key' unless $arg eq $new->to_base58;
	return $new;
    }
}
sub address { Bitcoin::Address->new(shift->public_point) }

package Bitcoin::Address;
our @ISA = qw( Bitcoin::Base58::Data    EC::DSA::PublicKey );
sub size() { 160 }
sub version() { defined($ENV{BITCOIN_TEST}) ? 1 : 0 }
sub data {
    my $this = shift->_no_class;
    use Bitcoin::Digest qw(hash160_bin);
    hash160_bin pack 'H2H*',
    '04', ((2**256+$this->x)*2**256+$this->y)->as_hex =~ s/0x1//r;
}

sub new {
    my $class = shift;
    my $arg = shift;
}

1;

__END__

=head1 TITLE

Bitcoin

=head1 SYNOPSIS

    use Bitcoin;

    say my $k = new Bitcoin::Key;
    my $addr = new Bitcoin::Address "1456someSi11yBi1c6inAddressXnkjn56dxx"
        or die "this is not a valid bitcoin address";
    
    say $k->address;
    say $k->public_point;
    my @signature = $k->sign("some message");

=head1 DESCRIPTION

Bitcoin is a peer-to-peer electronic cash system created in 2009 by Satoshi Nakamoto.  This module
and its submodules implement several tools for bitcoin-related operations.  This is part of a project aiming
at a full Perl implementation of the bitcoin protocol.

=head1 SEE ALSO

Bitcoin::Key, Bitcoin::Address, Bitcoin::Block, Bitcoin::Transaction, Bitcoin::Base58, EC

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

