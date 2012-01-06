#!/usr/bin/perl -w
# Satoshi Nakamoto's encoding in Perl.
package Bitcoin::Base58;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(encode decode);
use Bitcoin qw(BASE58);

use strict;
use warnings;

sub decode;
sub encode;

my %b58 = map { (BASE58)[$_] => $_ } 0 .. 57;

{
    use bigint;

    sub decode { shift =~ m/.$/p ? $b58{${^MATCH}} + 58*decode(${^PREMATCH}) : 0 }
    sub encode { my $_ = shift; return encode($_/58) . (BASE58)[$_%58] if $_ > 0 } 
}

package Bitcoin::Base58::Data;
# virtual base class for base58-encoded data (with version number and checksum)
use Digest::SHA qw(sha256);

# public methods
sub size();		# virtual constant function
sub default_version();	# virtual constant function
sub version;
sub data;
sub value;
sub checksum;
sub to_base58;
sub to_hex;
no warnings 'once';
*toBase58 = \&to_base58;
*toHex    = \&to_hex;

# "private" methods
sub _no_class    { my $_ = shift; die "class method call not implemented" unless ref; return $_ }
sub _no_instance { my $_ = shift; die "instance method call not implemented" if ref;  return $_ }

use overload fallback => 'TRUE', q("") => sub { shift->toBase58 };

sub value   { shift->_no_class->[0] }
sub data    { pack 'H*', shift->_no_class->value->as_hex =~ s/0x//r }
sub version { my $_ = shift; ref() ? $_->[1] // ref->default_version : $_->default_version }

{
    use integer;
    use bigint;

    sub new {
	my $class = shift->_no_instance;
	my $arg = shift;
	my $version = shift;
	if (ref($arg) eq 'Math::BigInt') { bless [ $arg, $version ], $class }
	elsif (ref($arg) eq $class) { return new $class $arg->value, $version // $arg->version }
	elsif ($arg =~ s,(?:0x)?([0-9a-f]{@{[$class->size/4]}}),$1,) { new $class pack('H*', $arg), $version }
	elsif ($arg =~ m/^[@{[Bitcoin::BASE58]}]+$/i)		{
	    my $new = bless [
		map { $_ / 256**4 % 2**$class->size, $_ / 256**4 / 2**$class->size }
		Bitcoin::Base58::decode $arg
	    ], $class;
	    die 'wrong checksum' if $new->checksum != Bitcoin::Base58::decode($arg) % 256**4;
	    return $new;
	}
	else  {
	    die 'argument is too big' if length(unpack 'b*', $arg) > $class->size;
	    new $class hex(unpack 'H*', $arg), $version;
	}
    }

    sub checksum {
	my $_ = shift;
	return ref() ? ref->checksum( $_->version()*2**$_->size + $_->value ) :
	hex unpack 'H8', sha256 sha256 pack 'H*',
	((0x100*2**$_->size + shift)->as_hex =~ s/0x1//r);
    }

    sub to_hex {
	my $_ = shift->_no_class;
	return +(((0x100 + $_->version) * 2**$_->size + $_->value) * 256**4 + $_->checksum)->as_hex =~ s/0x1//r;
    }

    sub to_base58 {
	my $_ = shift->_no_class;
	my $total_value = $_->version * 2**$_->size + $_->value;
	$total_value *= 256 ** 4;
	$total_value += $_->checksum;
	return +($_->version > 0 ? '' : '1') . Bitcoin::Base58::encode $total_value;
    }

}

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

