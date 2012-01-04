#!/usr/bin/perl -w
package Bitcoin::Block;
use strict;
use warnings;

use Bitcoin;
use Bitcoin::Database;
use Bitcoin::DataStream;
use Bitcoin::Transaction;

sub _no_class;
sub _no_instance;

sub new {
    my $class = shift->_no_instance;
    my $arg = $_[0];
    if (ref $arg eq 'Bitcoin::DataStream') {
	my $this = bless +{
	    version        => $arg->Read(Bitcoin::DataStream::INT32),
	    hashPrev       => unpack('H*', $arg->read_bytes(32)),
	    hashMerkleRoot => unpack('H*', $arg->read_bytes(32)),
	    nTime          => $arg->Read(Bitcoin::DataStream::UINT32),
	    nBits          => $arg->Read(Bitcoin::DataStream::UINT32),
	    nNonce         => $arg->Read(Bitcoin::DataStream::UINT32),
	}, $class;
	$this->check_proof_of_work;

	if ($this->{version} & (1 << 8)) {...}

	$this->{transactions} = [
	    map { new Bitcoin::Transaction $arg } 1 .. $arg->read_compact_size
	];
	return $this;
    }
    elsif (ref $arg eq 'HASH') {
	...
    }
    elsif (@_ > 1 and @_ % 2 == 0) { new $class +{ @_ } }
    elsif ($arg =~ /^[a-f\d]+$/) {
	Bitcoin::Database->import('blkindex');
	my $cursor = $Bitcoin::Database::blkindex->db_cursor;
	my ($prefix,) = map chr(length). $_, 'blockindex';
	my ($k, $v) = ($prefix, '');
	my ($kds, $vds);
	my ($nFile, $nBlockPos);
	if ($arg =~ s/^(?:0x)?([a-f\d]{64})$/$1/) {
	    $k .= reverse pack 'H*', $arg;
	    $cursor->c_get($k, $v, BerkeleyDB::DB_SET);
	    die 'no such block' unless $v;
	    die "block entry was removed" unless defined $v;
	    $vds = new Bitcoin::DataStream $v;
	    $vds->Read(Bitcoin::DataStream::INT32);  # version
	    $vds->read_bytes(32);  # hashNext
	    $nFile        = $vds->Read(Bitcoin::DataStream::UINT32);
	    $nBlockPos    = $vds->Read(Bitcoin::DataStream::UINT32);
	}
	else {
	    $cursor->c_get($k, $v, BerkeleyDB::DB_SET_RANGE);
	    my ($nHeight, $hash);
	    do {
		my ($kds, $vds) = map { new Bitcoin::DataStream $_ } $k, $v;
		$kds->read_string;
		$hash = unpack 'H*', reverse unpack 'a*', $kds->read_bytes(32);
		$vds->Read(Bitcoin::DataStream::INT32);  # version
		$vds->read_bytes(32);  # hashNext
		$nFile        = $vds->Read(Bitcoin::DataStream::UINT32);
		$nBlockPos    = $vds->Read(Bitcoin::DataStream::UINT32);
		$nHeight   = $vds->Read(Bitcoin::DataStream::INT32);

		$cursor->c_get($k, $v, BerkeleyDB::DB_NEXT);
		die "no such block (last inspected block was $hash)" if $k !~ /^$prefix/;
	    }
	    until $nHeight ~~ $arg or length($arg) > 8 and $hash =~ /$arg/;
	}
	return new $class Bitcoin::DataStream->new->map_file(
	    Bitcoin::Database::DATA_DIR . sprintf('/blk%04d.dat', $nFile),
	    $nBlockPos
	);
    }
    elsif ( not defined ref $arg ) { new $class new Bitcoin::DataStream $arg }
    else { die "wrong argument format" }
}

sub _no_instance { my $_ = shift; die "instance method call not implemented" if ref;  return $_ }
sub _no_class    { my $_ = shift; die "class method call not implemented" unless ref; return $_ }

sub header {
    my $this = shift->_no_class;
    pack 
    Bitcoin::DataStream::INT32 .
    'H64' .
    'H64' .
    Bitcoin::DataStream::UINT32 .
    Bitcoin::DataStream::UINT32 .
    Bitcoin::DataStream::UINT32 ,
    map $this->{$_}, qw(version hashPrev hashMerkleRoot nTime nBits nNonce);
}

sub serialize {
    my $this = shift->_no_class;
    return
    $this->header .
    ($this->{version} & (1 << 8) ? do {...} : '') .
    join '', map $_->serialize, @{$_->{transactions}};
}

sub check_proof_of_work {
    my $_ = shift;
    if (ref) { ref->check_proof_of_work($_->header, $_->{nBits}); return $_ }
    else {
	use integer;
	use bigint;
	my ($header, $nBits) = @_;
	my @n = map hex($_), +(0+$nBits)->as_hex  =~ /0x(..)(..)(..)(..)/;
	my $target = (($n[1]*256 + $n[2])*256 +$n[3]) * 256**($n[0] - 3);
	die "target doesn't provide minimum work" if $target > 2**(256 - Bitcoin::PROOF_OF_WORK_LIMIT) - 1;
	die "hash doesn't match nBits" if $target < hex unpack 'H*', reverse unpack 'a*', Bitcoin::hash $header;
    }
}

1;

__END__

=head1 TITLE

Bitcoin::Block

=head1 SYNOPSIS

    use Bitcoin::Block;

    my $block = new Bitcoin::Block 121899;
    my $block = new Bitcoin::Block '32fca6b8';
    my $block = new Bitcoin::Block $binary_block;
    my $block = new Bitcoin::Block -prevHash => '0x.....', -MerkleRoot => '.....', ...  ;
    my $block = new Bitcoin::Block { prevHash => '0x.....', MerkleRoot => '.....', ... } ;

    print "%s\n", unpack 'H*', $block->serialize();

    use Data::Dumper;
    print +Dumper $block;


=head1 DESCRIPTION

This class encapsulates a bitcoin block.

When a hash, a partial hash, or a block number is provided, the constructor opens the bitcoin
database and searches for the corresponding block.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
