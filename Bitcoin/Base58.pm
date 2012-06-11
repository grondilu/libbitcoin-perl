#!/usr/bin/perl -w
# Satoshi Nakamoto's encoding in Perl.
use strict;
use warnings;
use feature qw(say);

package Bitcoin::Base58;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(encode decode);
use Bitcoin::Util;

sub decode;
sub encode;

our @b58 = qw{
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
};
our %b58 = map { $b58[$_] => $_ } 0 .. 57;
our $b58 = qr/[@b58]/x;

{
    use bigint;
    use integer;

    sub decode { shift =~ m/$b58\Z/p ? $b58{${^MATCH}} + 58*decode(${^PREMATCH}) : 0 }
    sub encode { my $_ = shift; return $_ < 58 ? $b58[$_] : encode($_/58) . $b58[$_%58] } 
}

# Virtual base class for base58-encoded data (with version number and checksum)
package Bitcoin::Base58::Data;
use Digest::SHA qw(sha256);

# public methods
sub size();		# virtual constant function  (should be automatically inlined)
sub version();	        # virtual constant function  (should be automatically inlined)

# data and value represent the same data.  They define themselves reciprocally
# in a circular manner.  One of them MUST be defined in child class to break
# the circularity.
sub data;
sub value;

sub checksum;
sub to_base58;
sub to_hex;
{ no warnings 'once';
    *toBase58 = \&to_base58;
    *toHex    = \&to_hex;
}

# "private" methods
sub _no_class    { my $_ = shift; die "class method call not implemented" unless ref; return $_ }
sub _no_instance { my $_ = shift; die "instance method call not implemented" if ref;  return $_ }

# stringification
use overload q("") => sub { shift->to_base58 };

{
    use integer;
    use bigint;

    sub value {
	my $this = shift->_no_class;
	return hex unpack "H*", $this->data;
    }

    sub data  {
	my $this = shift->_no_class;
	return pack 'H*', (2**$this->size+$this->value)->as_hex =~ s/0x1//r;
    }

    sub value_from_address {
	my $this = shift->_no_instance;
	my $decode = Bitcoin::Base58::decode shift;
	return $decode / 256**4 % 2**$this->size;
    }

    sub checksum {
	use Bitcoin::Digest;
	my $this = shift->_no_class;
	return hex unpack 'H8', Bitcoin::Digest::hash256_bin pack 'H*',
	sprintf "%02X%s",
	$this->version,
	unpack("H*", $this->data);
    }

    sub to_hex {
	my $this = shift->_no_class;
	return sprintf "%02X%s%08X",
	$this->version,
	unpack("H*", $this->data),
	$this->checksum;
    }

    sub to_base58 {
	my $this = shift->_no_class;
	return +($this->version > 0 ? '' : '1') .
	Bitcoin::Base58::encode
	hex $this->to_hex;
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

    package My::Base58::Encoded::Class;
    @ISA = qw(Bitcoin::Base58::Data);

    sub size() { 1024 }
    sub version() { 1 }

=head1 DESCRIPTION

This module implements Satoshi Nakamoto's Base58 encoding.

It also contains a virtual class, Bitcoin::Base58::Data, which can be used
to implement the version+checksum system used with bitcoin addresses and private keys.

To do so, you need to inherit your class from Bitcoin::Base58::Data, and then
define C<size()> and C<version()>.  Make sure you explicitely use an
empty prototype.

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

