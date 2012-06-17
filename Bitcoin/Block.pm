#!/usr/bin/perl -w
use Bitcoin::Digest;
use Bitcoin::MerkleTree;

package Bitcoin::Block;
use IO::Uncompress::Bunzip2;
use strict;
use warnings;
use overload '""' => sub { use YAML; Dump shift };

sub new {
    my $class = shift;
    my $arg = $_[0];
    if (ref $arg eq 'Bitcoin::DataStream') {
	bless my $this = {}, $class;
	$this->{header} = new Bitcoin::Block::Header $arg;
	$this->{transactions} = [
	    map { Bitcoin::Transaction->new($arg) } 1 .. $arg->read_compact_size
	];
	# die "Merkle's tree root verification failed" if $this->header->hashMerkleRoot ne ($this->Merkle_tree)[-1];
	return $this;
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
	    }, $class); #->check_proof_of_work;
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

package Bitcoin::Block::Explorer;
require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(get_latest_block );
use LWP::Simple;
sub url() { "http://blockexplorer.com/" }
sub get_latest_block { get(url . "latest_block") // die "could not get latest block" }
sub get_block {
    my $this = shift;
    my $block_identifier = shift;
    use JSON;
    my $hash = get( url . "get_block_hash/$block_identifier" ) // die "could not get block's hash";
    my $rawblock = decode_json get(url . "rawblock/$hash") // die "could not get block $hash";
}

sub convert {
    my $class = shift;
    my $hash = shift;
    my $header = bless { # qw(version hashPrev hashMerkleRoot nTime nBits nNonce);
	version =>		$hash->{ver},
	hashPrev =>		scalar(reverse pack 'H*', $hash->{prev_block}),
	hashMerkleRoot =>	scalar(reverse pack 'H*', $hash->{mrkl_root}),
	nTime =>		$hash->{time},
	nNonce =>		$hash->{nonce},
	nBits =>		$hash->{bits},
    }, 'Bitcoin::Block::Header';
    my @tx;
    if(exists $hash->{tx}) {
	for( @{$hash->{tx}} ) {
	    push @tx, bless {
		txIn => [
		    map {
		    scriptSig => $_->{coinbase},
		    prevout_hash => $_->{prev_out}{hash},
		    prevout_n => $_->{prev_out}{n},
		    }, $_->{in}
		],
		sequence => $_->{sequence},
	    }, 'Bitcoin::Transaction';
	}
    }
}

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
