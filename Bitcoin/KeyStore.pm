#!/usr/bin/perl -w
use strict;
use warnings;

package Bitcoin::KeyStore;
use Bitcoin::Address;
use Bitcoin::PrivateKey;
our ($cipher, $passwd);

sub FETCH {
    my $_ = shift;
    my $addr = shift;
    my $encrypted = bless \$_->SUPER::FETCH($addr), 'Bitcoin::PrivateKey';
    return $encrypted->decrypt($cipher // $passwd);
}

sub STORE {
    my ($this, $key, $value) = @_;
    my $pubkey = Bitcoin::Address->new($key);
    my $privkey = Bitcoin::PrivateKey->new($value);
    die "incompatible version numbers" if $privkey->version != 128 + $pubkey->version;
    die "inconsistent entry:  key is not value's Bitcoin address" if $$pubkey ne $privkey->address->toBase58;
    return $this->SUPER::STORE($pubkey->toBase58, $privkey->encrypt($cipher // $passwd));
}

sub add {
    my $_ = shift;
    die "class method call not implemented" unless ref;
    my $arg = shift; 
    if (ref($arg) eq 'Bitcoin::PrivateKey') {
	my $address = $arg->address->toBase58;
	$_->SUPER::STORE($address, $arg->encrypt($cipher // $passwd));
	return $address;
    }
    else { $_->add(new Bitcoin::PrivateKey $arg) }
}

package Bitcoin::KeyStore::Basic; 		# corresponds to CBasicKeyStore
our @ISA = qw(Bitcoin::KeyStore);

package Bitcoin::KeyStore::Encrypted;		# corresponds to CCryptoKeyStore
our @ISA = qw(Bitcoin::KeyStore::Basic);

1;

__END__

=head1 TITLE

Bitcoin::KeyStore

=head1 SYNOPSIS

    use Bitcoin::KeyStore;

=head1 DESCRIPTION

Perl implementation of bitcoin's CKeyStore virtual class.

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

