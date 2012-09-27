#!/usr/bin/perl -w
use v5.14;
use strict;
use warnings;

package Bitcoin;
use EC::DSA qw(secp256k1);
use Bitcoin::Constants;
use Bitcoin::Base58;
use Bitcoin::Database; 
use Bitcoin::Block;

sub import {
    my $package = shift;

    import bigint;
    use overload;
    unless( ':nomagic' ~~ [ @_ ] or not Bitcoin::Constants::MAGIC) {
	# This allows magical recognition of bitcoin addresses or keys in
	# string literals.
	overload::constant q => sub {
	    my $s = shift;
	    if($s =~ /\A$Bitcoin::Base58::b58 {20,}\z/x) {
		my ($Base58Data, @error);
		$Base58Data = eval { new Bitcoin::Key $s };
		return $Base58Data unless $@;
		push @error, $@;
		$Base58Data = eval { new Bitcoin::Address $s };
		push @error, $@;
		return $Base58Data unless $@;
		warn "could not convert $s into a bitcoin address or key";
	    }
	    return $s;
	};
    }
}

package Bitcoin::Key;
our @ISA = qw(
    Bitcoin::Base58::Data
    EC::DSA::PrivateKey
);
sub size() { 256 }
sub version() { Bitcoin::Constants::THIS_IS_TEST ? 239 : 128 }
sub value { bless shift->copy(), 'Math::BigInt'; }
sub address { new Bitcoin::Address shift->public_key }

sub new {
    my $class = shift;
    my $arg = shift;
    if(
	defined $arg
	    and not ref $arg
	    and $arg =~ m/\A$Bitcoin::Base58::b58 {20,}\z/xi
    ) {
	my $new = bless $class->value_from_address($arg), $class;
	die 'invalid key' unless $arg eq $new->to_base58;
	return $new;
    }
    elsif( defined $arg and ref $arg and $arg->isa($class) ) { return $arg }
    elsif( not defined $arg ) { $class->random }
    else { $class->SUPER::new($arg) }
}

package Bitcoin::Address;
our @ISA = qw(Bitcoin::Base58::Data);
sub size() { 160 }
sub version() { Bitcoin::Constants::THIS_IS_TEST ? 111 : 0 }
sub data {
    my $this = shift;
    ref $this ? $this->{data} : $this->SUPER::data(@_);
}

sub new {
    my $class = shift;
    my $arg = shift;
    if(not defined $arg) {die "constructor requires an argument"}
    elsif( $arg =~ m/\A$Bitcoin::Base58::b58 {30,}\z/xi ) {
	my $new = bless { data => $class->data($class->value_from_address($arg)) }, $class;
	die "invalid address $arg" unless $arg eq $new->to_base58;
	return $new;
    }
    elsif( not ref $arg ) { die "unknown argument format" }
    elsif( $arg->isa('EC::DSA::PublicKey') ) {
	use Bitcoin::Digest qw(hash160_bin);
	return bless { data => hash160_bin $arg->serialize() }, $class;
    }
    elsif( $arg->isa('EC::Point') ) {
	return $class->new(bless $arg, 'EC::DSA::PublicKey');
    }
    elsif ($arg->isa($class)) { return $arg }
    else { die "unknown argument type" }
}

1;

__END__

=head1 TITLE

Bitcoin

=head1 SYNOPSIS

    use Bitcoin;

    say my $k = new Bitcoin::Key;
    say my $k = random Bitcoin::Key; # same thing

    my $addr = new Bitcoin::Address "1456someSi11yBi1c6inAddressXnkjn56dxx"
        or die "this is not a valid bitcoin address";
    my $addr = "1456someSi11yBi1c6inAddressXnkjn56dxx";
    
    say $k->address;
    say "5JYazF125AwHtaDBDgBFsFc7Q7PKtoePndwJN2z1YfTBN3ThKx8"->address;
    say $k->public_point;
    my @signature = $k->sign("some message");

=head1 DESCRIPTION

Bitcoin is a peer-to-peer electronic cash system created in 2009 by Satoshi Nakamoto.  This module
and its submodules implement several tools for bitcoin-related operations.  This is part of a project aiming
at a full Perl implementation of the bitcoin protocol.

This particular module contains two classes:

- Bitcoin::Key encapsulates a bitcoin private key.  It inherits from the
virtual class Bitcoin::Base58::Data and EC::DSA::PrivateKey.

- Bitcoin::Address encapsulates a bitcoin public key, aka a bitcoin address.
It inherits from Bitcoin::Base58::Data.

=head2 Magic litteral recognition

By default the library recognizes bitcoin addresses or keys in string literals.  This
allows you to write something like:

    say "5JYazF125AwHtaDBDgBFsFc7Q7PKtoePndwJN2z1YfTBN3ThKx8"->address;

To avoid this magic behavior, you can either import the library with a ':nomagic' option:

    use Bitcoin qw(:nomagic);

or set the environment variable BITCOIN_MAGIC to 'no', 'none' or 'false'.

=head2 Modular and Elliptic curve arithmetics

Bitcoin::Key inherits from EC::DSA::PrivateKey, which inherits from
Math::BigInt, with overload arithmetics operators in order to support modular
arithmetics. Therefore you can multiply a private key by an integer, and you'll
get an other private key (the multiplication here is the modular multiplication
whose modulus is the order of the secp256k1 sub-group).

You can also multiply or add public keys made out of private keys, as such a
public keys derive from EC::Point.  You'll get elliptic curve arithmetics.

This allows secure agreement on a common public key, as in the following example.

=head3 Diffie-Hellman-like protocol

Alice want to send Bob some bitcoins in exchange from some product to be received by mail,
but she wants a way to make sure Bob will not be able to cash the bitcoins in until she
actually receives the expected product.

Both of them generate new, random bitcoin key, and both of them compute the
corresponding public key.

    A> my $key = random Bitcoin::Key;
    A> my $pubic_key_A = public_key $key;

    B> my $key = random Bitcoin::Key;
    B> my $pubic_key_B = public_key $key;

They communicate one an other their respective public keys, they multiply it by their
own private key, and they get the corresponding Bitcoin address.

    A> my $common_address = new Bitcoin::Address $key * $public_key_B
    B> my $common_address = new Bitcoin::Address $key * $public_key_A

They verify that their common address is really the same by communicating it
(or part of it) to one another.

At this point none of them has the private key matching this bitcoin address.
Alice can now send her bitcoins to this address.

Once Alice has received her product, she communicates to Bob her initial private key,
and Bob can find the private key of the common address by running:

    B> my $cash_in_key = new Bitcoin::Key $key * $key_A;

=head1 SEE ALSO

Bitcoin::Block, Bitcoin::Transaction, Bitcoin::Base58, EC::DSA

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

