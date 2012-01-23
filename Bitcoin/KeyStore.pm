#!/usr/bin/perl -w
package Bitcoin::KeyStore;
@ISA = qw(Tie::Hash);
use strict;
use warnings;
use Bitcoin::Address;
use Bitcoin::Key;

sub STORE {
    my ($this, $key, $value) = @_;
    my $address = new Bitcoin::Address     $key;
    my $secret  = new Bitcoin::Key::Secret $value;
    die "incompatible version numbers" if $secret->version != 128 + $address->version;
    die "inconsistent entry" if $address ne $secret->address;
    return SUPER::STORE $this $address->toBase58, $secret;
}

sub add {
    my $this = shift;
    die "class method call not implemented" unless ref $this;
    my $arg = shift; 
    return SUPER::STORE $this $arg->address->toBase58, $arg;
}

package Bitcoin::KeyStore::Basic; 		
# This class corresponds to CBasicKeyStore but is merely an alias to Bitcoin::KeyStore
our @ISA = qw(Bitcoin::KeyStore);

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

