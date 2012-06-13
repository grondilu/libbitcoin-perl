#!/usr/bin/perl -w
use Bitcoin;
use Bitcoin::Database;

package Bitcoin::Block;
our @ISA = qw(Bitcoin::Block::Header);  # see below
use strict;
use warnings;

sub new {
    my $class = shift->_no_instance;
    my $arg = $_[0];
    if (ref $arg eq 'Bitcoin::DataStream') {
	my $this = SUPER::new $class $arg;

	if (not defined($ENV{BITCOIN_TEST}) and $this->{version} & (1 << 8)) {
	    use Bitcoin::DataStream qw(INT32 BYTE);
	    my $merkle_tx = new Bitcoin::Transaction $arg;
	    $merkle_tx->{chainMerkleBranch} = $arg->Read(BYTE . 32*$arg->read_compact_size);
	    $merkle_tx->{chainIndex} = $arg->Read(INT32);
	    $merkle_tx->{parentBlock} = SUPER::new $class $arg;
	    $this->{merkleTx} = $merkle_tx;
	}

	$this->{transactions} = [ map { Bitcoin::Transaction->new($arg) } 1 .. $arg->read_compact_size ];

	die "Merkle's tree root verification failed"
	if pack('H*', $this->{hashMerkleRoot}) ne reverse +($this->Merkle_tree)[-1];

	return $this;
    }
    else { return SUPER::new $class @_ }
}

sub unbless {
    my $this = shift;
    +{
	map {
	$_ => $_ eq 'transactions' ?
	[ map { $_->unbless } @{$this->{$_}} ] :
	$this->{$_}
	} keys %$this
    }
}

sub serialize {
    use Bitcoin::DataStream;
    my $this = shift->_no_class;
    my $stream = new Bitcoin::DataStream;
    Write $stream SUPER::serialize $this;
    Write $stream $this->{version} & (1 << 8) ? do {...} : '';
    my @transactions = @{$this->{transactions}};
    write_compact_size $stream scalar @transactions;
    Write $stream $_->serialize->input for @transactions;
    return $stream;
}
sub get_hash { my $this = shift->_no_class; Bitcoin::Digest::hash256_bin $this->SUPER::serialize }

sub Merkle_tree {
    # This is a straightforward translation of Satoshi's code
    my $this = shift->_no_class;
    my @tree;
    my @transactions = @{$this->{transactions}};
    push @tree, $_->get_hash for @transactions;
    for( my $j = 0, my $size = @transactions; $size > 1; $size = int( ($size + 1) / 2 ) ) {
	for ( my $i = 0; $i < $size; $i += 2 ) {
	    my $i2 = $i + 1 < $size - 1 ? $i + 1 : $size - 1;
	    push @tree, Bitcoin::Digest::hash256_bin $tree[$j + $i] . $tree[$j + $i2];
	}
	$j += $size;
    }
    return @tree;
}

package Bitcoin::Block::Header;

use Bitcoin::DataStream qw(:types);
use Bitcoin::Transaction;

use overload
'""' => sub {
    my $_ = shift;
    sprintf 'Bitcoin block created on %s: %s',
    qx(date -Rd \@$_->{nTime}) =~ s/\n//r,
    unpack 'H*', reverse $_->get_hash;
},
;

sub _no_class;
sub _no_instance;

sub new {
    my $class = shift->_no_instance;
    my $arg = $_[0] // return;
    if (ref $arg eq 'Bitcoin::DataStream') {
	return bless({
		version        => $arg->Read(INT32),
		hashPrev       => unpack('H*', reverse $arg->Read(BYTE . 32)),
		hashMerkleRoot => unpack('H*', reverse $arg->Read(BYTE . 32)),
		nTime          => $arg->Read(UINT32),
		nBits          => $arg->Read(UINT32),
		nNonce         => $arg->Read(UINT32),
	    }, $class)->check_proof_of_work;
    }
    elsif (ref $arg ~~ [ qw(HASH Regexp) ]) {
	my $index = new Bitcoin::Disk::Block::Index $arg;
	my @result = map { new $class $_ } keys %$index;
	return @result;
    }
    elsif ($arg =~ s/^(?:0x)?([a-f\d]{64})$/$1/) {
	my $index = new Bitcoin::Disk::Block::Index $arg;
	return new $class Bitcoin::DataStream->new->map_file(
	    sprintf('%s/blk%04d.dat', $Bitcoin::data_dir, $index->{$arg}{nFile}),
	    $index->{$arg}{nBlockPos})
    }
    elsif ($arg =~ /^\d+$/)        {
	use Bitcoin::Constants;
	my @preceding_checkpoint =
	    sort { $a->{nHeight} <=> $b->{nHeight} } 
	    grep { $_->{nHeight} <= $arg }
	    map eval { Bitcoin::Disk::Block::Index->new($_)->{$_} },
	    Bitcoin::Constants::GENESIS, keys %{+Bitcoin::Constants::CHECKPOINTS};
	my $indexed_block = pop @preceding_checkpoint;
	my $hash = Bitcoin::Constants::GENESIS;
	die 'could not find indexed block' unless defined $indexed_block;
	while ($indexed_block->{nHeight} < $arg) {
	    $hash = unpack 'H*', reverse $indexed_block->{hashNext} // die 'reached block chain end';
	    $indexed_block = Bitcoin::Disk::Block::Index->new($hash)->{$hash};
	}
	return new $class $hash if $indexed_block->{nHeight} == $arg;
	die 'no such block';
    }
    elsif (@_ > 1 and @_ % 2 == 0) { new $class +{ @_ } }
    elsif ( not defined ref $arg ) { new $class new Bitcoin::DataStream $arg }
    else { die "wrong argument format" }
}

sub _no_instance { my $_ = shift; die "instance method call not implemented" if ref;  return $_ }
sub _no_class    { my $_ = shift; die "class method call not implemented" unless ref; return $_ }

sub copy {
    my $this = shift->_no_class;
    ref($this)->new($this->serialize);
}

sub previous {
    my $this = shift->_no_class;
    my $n = shift // 1;
    die 'negative argument' if $n < 0;
    return
    $n == 0 ? $this :
    ref($this)->new($this->{hashPrev})->previous(--$n);
}

sub serialize {
    my $this = shift->_no_class;
    pack
    INT32  .
    'a32a32' .
    UINT32 .
    UINT32 .
    UINT32 ,
    $this->{version},
    ( map { scalar reverse pack 'H64', $this->{$_} } qw(hashPrev hashMerkleRoot) ),
    map $this->{$_}, qw(nTime nBits nNonce);
}

sub get_hash { my $this = shift->_no_class; Bitcoin::Digest::hash256_bin $this->serialize }
sub get_hash_hex { my $this = shift->_no_class; unpack 'H*', reverse $this->get_hash }

sub target {
    my $this = shift;
    my $nBits = ref $this ? $this->{nBits} : shift;
    my ($size, $n) = map hex($_), sprintf("%08x", $nBits) =~ /(..)(.{6})/;
    return $n * 256**($size - 3);
}

sub work { 64 - log(shift->target)/log(16) }


sub check_proof_of_work {
    my $_ = shift;
    if (ref) { ref->check_proof_of_work($_->get_hash_hex, $_->{nBits}); return $_ }
    else {
	use bigint;
	my ($hash_hex, $nBits) = @_;
	my $target = $_->target($nBits);
	die "target doesn't provide minimum work" if $target > 2**(256 - 32) - 1;
	die "hash doesn't match nBits" if $target < hex $hash_hex;
    }
}

package Bitcoin::Block::Index;   # aka CBlockIndex

sub new {
    my $class = shift; die 'instance method call not implemented for this class' if ref $class;
    my $arg = shift;
    if    (ref $arg eq 'Bitcoin::Block')      {...}
    elsif (ref $arg eq 'Bitcoin::DataStream') {
	use Bitcoin::DataStream qw(:types);
	return bless {
	    version   => $arg->Read(INT32),
	    hashNext  => $arg->Read(BYTE . 32),
	    nFile     => $arg->Read(UINT32),
	    nBlockPos => $arg->Read(UINT32),
            nHeight   => $arg->Read(INT32),
	}, $class;
    }
    else {...}
}

package Bitcoin::Disk::Block::Index;  # aka CDiskBlockIndex
our @ISA = qw(Bitcoin::Disk::Index);
sub prefix()         { 'blockindex' }
sub indexed_object() { 'Bitcoin::Block::Index' }
sub filename()       { 'blkindex.dat' }

package Bitcoin::Block::Locator;
# TODO

1;

__END__

=head1 TITLE

Bitcoin::Block

=head1 SYNOPSIS

    use Bitcoin::Block;

    my $block = new Bitcoin::Block Bitcoin::GENESIS;
    my $block = new Bitcoin::Block 121_899;
    my @block = new Bitcoin::Block qr/^0+19/;
    my $block = new Bitcoin::Block $binary_block;
    my @block = new Bitcoin::Block -prevHash => '0x.....', -MerkleRoot => '.....', ...  ;
    my @block = new Bitcoin::Block { prevHash => '0x.....', MerkleRoot => '.....', ... } ;

    # human-friendly summary
    say $block;

    # Full dump (using YAML for instance)
    use YAML;
    print +Dump $block;
    print +Dump unbless $block;

    print unpack 'H*', serialize $block;

=head1 DESCRIPTION

This class encapsulates a bitcoin block.

When a hash, a regex, or a block number is provided, the constructor opens the bitcoin
database and searches for the corresponding block(s).

In scalar context, the constructor returns a single object if the result of the search was unique.
Overwise it returns the number of results.

In list context, it returns a possibly empty list of matching objects.

Proof of work and Merkle root are verified during instanciation.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
