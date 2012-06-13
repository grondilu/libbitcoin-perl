#!/usr/bin/perl -w
package Bitcoin::KeyStore;  # aka CKeyStore
require Tie::StdHash;
@ISA = qw(Tie::StdHash);
use strict;
use warnings;
use threads;
use threads::shared;

sub _no_class    { my $_ = shift; die 'class method call not implemented'    if ref     }
sub _no_instance { my $_ = shift; die 'instance method call not implemented' unless ref }

# This is a virtual class, so the following methods are only declared
sub add_key;
sub have_key;
sub get_key;
sub get_pubkey;
sub generate_new_key;

package Bitcoin::KeyStore::Basic;  # aka CBasicKeyStore
our @ISA = qw(Bitcoin::KeyStore);

sub add_key {
    my $this = shift->_no_class;
    my $secret = shift;
    do {...} unless ref $secret eq 'Bitcoin::Key::Secret';
    { lock $this; $this->STORE($secret->address->toBase58, $secret) }
}
sub have_key {
    my $this = shift->_no_class;
    my $address = shift;
    my $result;
    { lock $this; $result = $this->EXISTS($address->toBase58) }
    return $result;
}
sub get_key {
    my $this = shift->_no_class;
    my $address = shift;
    my $result;
    { lock $this; $result = $this->FETCH($address->toBase58) }
    return $result;
}

package Bitcoin::KeyStore::Encrypted;
# This class corresponds to CCryptoKeyStore but is much more rudimentary
our @ISA = qw(Bitcoin::KeyStore);

1;

__END__

=head1 TITLE

Bitcoin::KeyStore

=head1 SYNOPSIS

    use Bitcoin::KeyStore;

=head1 DESCRIPTION

Perl implementation of bitcoin's CKeyStore virtual class.

This is quite different from the vanilla C++ implementation, though.  The base
class, Bitcoin::KeyStore, is not virtual and does not implement interprocess
locking protection systems.

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

