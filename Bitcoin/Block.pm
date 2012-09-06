#!/usr/bin/perl -w
use Bitcoin::Digest;
require Bitcoin::Constants;

package Bitcoin::Block;
use strict;
use warnings;
use overload '""' => sub { use YAML; Dump shift };

sub depth { shift->{depth} }
sub work { shift->{work} }
sub new {
    my $class = shift;
    my $arg = $_[0];
    if (ref $arg eq 'Bitcoin::DataStream') {
	bless my $this = {}, $class;
	$this->{header} = new Bitcoin::Block::Header $arg;
	$this->{transactions} = [
	    map { Bitcoin::Transaction->new($arg) } 1 .. $arg->read_compact_size
	];
	die "Merkle's tree root verification failed" if $this->header->hashMerkleRoot ne ($this->Merkle_tree)[-1];
	return $this;
    }
    elsif( uc $arg =~ /^\A[[:xdigit:]]{64}\Z/ ) {
	my $index = new Bitcoin::Disk::Block::Index $arg;
	return new $class Bitcoin::DataStream->new->map_file(
	    sprintf('%s/blk%04d.dat', Bitcoin::Constants::DATA_DIR, $index->{$arg}{nFile}),
	    $index->{$arg}{nBlockPos});
    }
    elsif( uc $arg =~ /^\A[[:xdigit:]]{10,}\Z/ ) {
	$class->new(Bitcoin::DataStream->new(pack 'H*', $arg));
    }
    else { die 'unknown argument type' }
}

sub header { shift->{header} }
sub transactions { shift->{transactions} }
sub serialize {
    use Bitcoin::DataStream;
    my $this = shift;
    my $stream = new Bitcoin::DataStream;
    Write $stream $this->header->serialize;
    my @transactions = @{$this->{transactions}};
    write_compact_size $stream scalar @transactions;
    Write $stream $_->serialize->input for @transactions;
    return $stream;
}
sub get_hash { shift->header->get_hash }

sub Merkle_tree {
    # This is a straightforward translation of Satoshi's code
    my $this = shift;
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

sub update {
    use Bitcoin::Constants;
    my $this = shift;
    if(unpack("H*", reverse $this->get_hash) eq Bitcoin::Constants::GENESIS) {
	$this->{depth} = 0; $this->{work} = $this->header->work;
	return $this->dbupdate;
    }
    my $previous_block = load $this->header->hashPrev;
    if(not defined $previous_block) {
	die 'could not find previous block';
    }
    elsif(defined $previous_block->depth and defined $previous_block->work) {
	$this->{depth} = $previous_block->depth + 1;
	$this->{work} = $previous_block->work + $this->work;
    }
    else {
	eval { $previous_block->update };
	$this->update unless $@;
    }
}

package Bitcoin::Block::Header;
use Bitcoin::DataStream qw(:types);
use Bitcoin::Transaction;

sub _no_instance { my $_ = shift; die "instance method call not implemented" if ref;  return $_ }
sub _no_class    { my $_ = shift; die "class method call not implemented" unless ref; return $_ }

sub version		{ shift->_no_class->{version}        // die 'undefined version' }
sub hashPrev		{ shift->_no_class->{hashPrev}       // die 'undefined hashPrev' }
sub hashMerkleRoot	{ shift->_no_class->{hashMerkleRoot} // die 'undefined hashMerkleRoot' }
sub nTime		{ shift->_no_class->{nTime}          // die 'undefined nTime' }
sub nBits		{ shift->_no_class->{nBits}          // die 'undefined nBits' }
sub nNonce		{ shift->_no_class->{nNonce}         // die 'undefined nNonce' }

sub new {
    my $class = shift->_no_instance;
    my $arg = $_[0] // return;
    if (ref $arg eq 'Bitcoin::DataStream') {
	return bless({
		version        => $arg->Read(INT32),
		hashPrev       => $arg->Read(BYTE . 32),
		hashMerkleRoot => $arg->Read(BYTE . 32),
		nTime          => $arg->Read(UINT32),
		nBits          => $arg->Read(UINT32),
		nNonce         => $arg->Read(UINT32),
	    }, $class)->check_proof_of_work;
    }
    elsif ( ref $arg eq 'HASH' ) {
	return bless($arg, $class)->check_proof_of_work;
    }
    elsif ( not defined ref $arg ) { $class->new(Bitcoin::DataStream->new($arg)) }
    else { die "wrong argument format" }
}

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
    pack join('', INT32, 'a32a32', UINT32, UINT32, UINT32),
    map $this->{$_}, qw(version hashPrev hashMerkleRoot nTime nBits nNonce);
}

sub get_hash { my $this = shift->_no_class; Bitcoin::Digest::hash256_bin $this->serialize }
sub get_hash_hex { my $this = shift->_no_class; unpack 'H*', reverse $this->get_hash }

sub target {
    my $this = shift;
    my $nBits = ref $this ? $this->{nBits} : shift;
    my ($size, $n) = map hex($_), sprintf("%08x", $nBits) =~ /(..)(.{6})/;
    return $n * 256**($size - 3);
}

sub work { 256 - log(shift->target)/log(2) }
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

1;

__END__

=head1 TITLE

Bitcoin::Block

=head1 SYNOPSIS

    use Bitcoin::Block;

    my $block = new Bitcoin::Block $binary_block;
    my $block = load Bitcoin::Block Bitcoin::GENESIS;
    my $block = load Bitcoin::Block 121_899;
    my @block = search Bitcoin::Block qr/^0+19/;

    # serialize
    say unpack 'H*', serialize $block;

    # human-friendly dump
    say $block;

    # updates work and depth
    update $block;

    # saves on database
    save $block;

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
