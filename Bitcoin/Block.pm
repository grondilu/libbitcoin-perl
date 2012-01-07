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
	my $this = bless({
		version        => $arg->Read(Bitcoin::DataStream::INT32),
		hashPrev       => unpack('H*', reverse $arg->Read(Bitcoin::DataStream::BYTE . 32)),
		hashMerkleRoot => unpack('H*', reverse $arg->Read(Bitcoin::DataStream::BYTE . 32)),
		nTime          => $arg->Read(Bitcoin::DataStream::UINT32),
		nBits          => $arg->Read(Bitcoin::DataStream::UINT32),
		nNonce         => $arg->Read(Bitcoin::DataStream::UINT32),
	    }, $class)->check_proof_of_work;

	return $this if $class =~ /::HEADER$/i;

	if ($this->{version} & (1 << 8)) {
	    my $merkle_tx = new Bitcoin::Transaction $arg;
	    $merkle_tx->{chainMerkleBranch} = $arg->Read(Bitcoin::DataStream::BYTE . (32*$arg->read_compact_size));
	    $merkle_tx->{chainIndex} = $arg->Read(Bitcoin::DataStream::INT32);
	    $merkle_tx->{parentBlock} = ($class.'::HEADER')->new($arg);
	}

	$this->{transactions} = [
	    map { new Bitcoin::Transaction $arg } 1 .. $arg->read_compact_size
	];
	return $this;
    }
    elsif (ref $arg eq 'HASH') {
	...
    }
    elsif (@_ > 1 and @_ % 2 == 0) { new $class +{ @_ } }
    elsif ($arg =~ /^[a-f\d]+$/ or ref $arg eq 'Regexp') {
	import Bitcoin::Database 'blkindex';
	my $cursor = $Bitcoin::Database::blkindex->db_cursor;
	my ($prefix,) = map chr(length). $_, 'blockindex';
	my ($k, $v) = ($prefix, '');
	my ($nFile, $nBlockPos);
	if ($arg =~ s/^(?:0x)?([a-f\d]{64})$/$1/) {
	    $k .= reverse pack 'H*', $arg;
	    $cursor->c_get($k, $v, BerkeleyDB::DB_SET);
	    die 'no such block' if $cursor->status;
	    die "block entry was removed" unless defined $v;
	    my $vds = new Bitcoin::DataStream $v;
	    $vds->Read(Bitcoin::DataStream::INT32);  # version
	    $vds->Read(Bitcoin::DataStream::BYTE . 32);  # hashNext
	    $nFile        = $vds->Read(Bitcoin::DataStream::UINT32);
	    $nBlockPos    = $vds->Read(Bitcoin::DataStream::UINT32);
	}
	elsif ($arg =~ /^\d+$/ or ref $arg eq 'Regexp') {
	    my @result;
	    SEARCH: {
		$cursor->c_get($k, $v, BerkeleyDB::DB_SET_RANGE);
		do {
		    my ($kds, $vds) = map { new Bitcoin::DataStream $_ } $k, $v;
		    last SEARCH if $kds->read_string ne 'blockindex';
		    my $hash = unpack 'H*', reverse $kds->Read(Bitcoin::DataStream::BYTE . 32);
		    if (ref $arg eq 'Regexp') { push @result, $hash if $hash =~ $arg }
		    else {
			$vds->Read(Bitcoin::DataStream::INT32);  # version
			$vds->Read(Bitcoin::DataStream::BYTE . 32);  # hashNext
			$nFile        = $vds->Read(Bitcoin::DataStream::UINT32);
			$nBlockPos    = $vds->Read(Bitcoin::DataStream::UINT32);
			my $nHeight   = $vds->Read(Bitcoin::DataStream::INT32);
			last SEARCH if $nHeight == $arg;
		    }
		} until $cursor->c_get($k, $v, BerkeleyDB::DB_NEXT);
	    }
	    if (@result > 1) { return { map { $_ => ($class.'::HEADER')->new($_) } @result } }
	    elsif (@result == 1) { return new $class shift @result }
	    elsif (ref $arg eq 'Regexp') { die "no matching block" }
	}
	else { die 'wrong argument format' }
	return new $class Bitcoin::DataStream->new->map_file(
	    sprintf('%s/blk%04d.dat', Bitcoin::DATA_DIR, $nFile),
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
    Bitcoin::DataStream::INT32  .
    'a32a32' .
    Bitcoin::DataStream::UINT32 .
    Bitcoin::DataStream::UINT32 .
    Bitcoin::DataStream::UINT32 ,
    $this->{version},
    ( map { scalar reverse pack 'H64', $this->{$_} } qw(hashPrev hashMerkleRoot) ),
    map $this->{$_}, qw(nTime nBits nNonce);
}

sub unbless {
    my $this = shift;
    +{
	map {
	$_ => $_ eq 'transactions' ?
	[ map { +{ %$_ } } @{$this->{$_}} ] :
	$this->{$_}
	} keys %$this
    }
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
	use bigint;
	my ($header, $nBits) = @_;
	my ($size, $n) = map hex($_), (0+$nBits)->as_hex  =~ /0x(..)(.{6})/;
	my $target = $n * 256**($size - 3);
	die "target doesn't provide minimum work" if $target > 2**(256 - Bitcoin::PROOF_OF_WORK_LIMIT) - 1;
	die "hash doesn't match nBits" if $target < hex Bitcoin::hash_hex $header;
    }
}

package Bitcoin::Block::HEADER;
our @ISA = qw(Bitcoin::Block);

1;

__END__

=head1 TITLE

Bitcoin::Block

=head1 SYNOPSIS

    use Bitcoin::Block;

    my $block = new Bitcoin::Block 121_899;
    my $block = new Bitcoin::Block Bitcoin::GENESIS;
    my @block = new Bitcoin::Block qr/^0+19/;
    my $block = new Bitcoin::Block $binary_block;
    my $block = new Bitcoin::Block -prevHash => '0x.....', -MerkleRoot => '.....', ...  ;
    my $block = new Bitcoin::Block { prevHash => '0x.....', MerkleRoot => '.....', ... } ;

    print Bitcoin::hash_hex $block->header;

    use Data::Dumper;
    print +Dumper $block;
    print +Dumper unbless $block;

    print unpack 'H*', serialize $block;

=head1 DESCRIPTION

This class encapsulates a bitcoin block.

When a hash, a regex, or a block number is provided, the constructor opens the bitcoin
database and searches for the corresponding block(s).

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
