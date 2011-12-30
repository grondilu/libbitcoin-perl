#!/usr/bin/perl -w
package Bitcoin::Wallet;
require DB_File;
@ISA = qw(DB_File);

use strict;
use warnings;

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
1;

__END__

=head1 TITLE

Bitcoin::Wallet

=head1 SYNOPSIS

    use Bitcoin::Wallet;

    $Bitcoin::Wallet::passwd = 'some password';

    tie my %wallet, 'Bitcoin::Wallet', '/path/to/my/wallet';
    END { untie %wallet }

    $wallet{foo} = 'bar';  # dies immediately as none of this is bitcoin related

    use Bitcoin::PrivateKey;
    my $key = new Bitcoin::PrivateKey;
    $wallet{$key->address} = $$key;
    $wallet{1StupidFakeAddress31415z} = $$key;   # should die as the address is not valid;


=head1 DESCRIPTION

This class provides tie mechanism for a bitcoin wallet.

It has a simple publickey => privatekey structure, but it provides encryption
and prevents user from entering anything but valid keys in the database.

This class DOES NOT implement a bitcoin wallet such as the one that is used in
the bitcoin vanilla software.

Other data such as transaction history, blocks or contacts should
be stored somewhere else.

=head1 TODO

The class can only store instances of Bitcoin::PrivateKey.  I would be better if it was
more generic and could store any child class.

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

