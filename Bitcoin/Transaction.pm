#!/usr/bin/perl
package Bitcoin::Transaction;
use strict;
use warnings;

sub _no_class;
sub _no_instance;

use Bitcoin::Script;
use Bitcoin::DataStream qw( :types );

sub serialize;
sub verify;

sub new {
    my $class = shift->_no_instance;
    my $arg = $_[0] // do {...};
    if (ref $arg eq 'Bitcoin::DataStream') {
	bless +{
	    version     => $arg->Read(INT32),                                            # 1
	    txIn	=> [
		map +{  
		    prevout_hash	=> unpack('H*', reverse $arg->read_bytes(32)),   # 3
		    prevout_n		=> $arg->Read(UINT32),                           # 4
		    scriptSig		=> Bitcoin::Script->new($arg->Read(STRING)),     # 5
		    sequence		=> $arg->Read(UINT32),                           # 6
		},
		1 .. $arg->read_compact_size                                             # 2
	    ],
	    txOut	=> [
		map +{  
		    value		=> $arg->Read(INT64),                            # 8
		    scriptPubKey	=> Bitcoin::Script->new($arg->Read(STRING)),     # 9
		},
		1 .. $arg->read_compact_size                                             # 7
	    ],
	    lockTime 	=> $arg->Read(UINT32),                                           # 10
	}, $class;
    }
    elsif(not ref $arg) { $class->new(new Bitcoin::DataStream $arg) }
    else {...}
}

sub serialize {
    my $this = shift->_no_class;
    my $stream = new Bitcoin::DataStream;
    Write $stream INT32, $this->{version};                                               #  1
    write_compact_size $stream scalar @{$this->{txIn}};                                  #  2
    for my $txIn (@{$this->{txIn}}) {
	Write $stream scalar reverse pack 'H64', $txIn->{prevout_hash};                  #  3
	Write $stream UINT32, $txIn->{prevout_n};                                        #  4
	Write $stream STRING, pack 'H*', $txIn->{scriptSig}->code;                       #  5
	Write $stream UINT32, $txIn->{sequence};                                         #  6
    }
    write_compact_size $stream scalar @{$this->{txOut}};                                 #  7
    for my $txOut (@{$this->{txOut}}) {
	Write $stream INT64, $txOut->{value};                                            #  8
	Write $stream STRING, pack 'H*', $txOut->{scriptPubKey}->code;                   #  9
    }
    Write $stream UINT32, $this->{lockTime};                                             # 10
    return $stream;
}

sub copy {
    my $this = shift->_no_class;
    ref($this)->new($this->serialize);
}
{ no warnings 'once'; *clone = \&copy }

sub verify {
    my $this = shift->_no_class;
    for (my $i = 0; $i < @{$this->{txIn}}; $i++) {
	my $txIn = $this->{txIn}[$i];
	next if $txIn->{prevout_hash} =~ /\A0+\Z/;
	$txIn->{scriptSig}();
	my $stripped_copy = $this->strip_sig($i);
	die 'stripped_copy is not defined' unless defined $stripped_copy;
	ref($this)                 ->
	new($txIn->{prevout_hash}) ->
	{txOut} [$txIn->{prevout_n}] {scriptPubKey}
	( $stripped_copy );
    }
    return $this;
}

sub strip_sig {
    my $copy = shift->_no_class->copy;
    my $txIn = $copy->{txIn}[shift];
    my $hashType = shift // 1;
    $_->{scriptSig} = new Bitcoin::Script for @{$copy->{txIn}};
    $txIn->{scriptSig} = ref($copy) ->
    new($txIn->{prevout_hash}) ->
    {txOut} [$txIn->{prevout_n}] {scriptPubKey};
    return $copy;
}

sub unbless {
    my $this = shift->_no_class;
    my ($txIn, $txOut) = map $this->{$_}, qw(txIn txOut);
    +{
	version => $this->{version}, lockTime => $this->{lockTime},
	txIn    => [ map +{
		scriptSig => $_->{scriptSig}->unbless,
		prevout_hash => $_->{prevout_hash},
		prevout_n => $_->{prevout_n},
		sequence => $_->{sequence},
	    }, @$txIn ],
	txOut    => [ map +{
		scriptPubKey => $_->{scriptPubKey}->unbless,
		value => $_->{value}
	    }, @$txOut ]
    }
}

sub get_hash {
    use Bitcoin::Digest;
    my $this = shift->_no_class;
    Bitcoin::Digest::hash256_bin $this->serialize->input;
}
sub get_hash_hex { unpack 'H*', reverse shift->get_hash }

sub _no_instance { my $_ = shift; die "instance method call not implemented" if ref;  return $_ }
sub _no_class    { my $_ = shift; die "class method call not implemented" unless ref; return $_ }
1;

__END__

=head1 TITLE

Bitcoin::Transaction;

=head1 SYNOPSIS

    use Bitcoin::Transaction;

    my $tx = new Bitcoin::Transaction '87a157f3fd88ac7907c05fc55e271dc4acdc5605d187d646604ca8c0e9382e03';
    my @tx = new Bitcoin::Transaction qr/^87a157/;

    say +Data::Dumper $x;
    say $_->get_hash_hex for @tx;

=head1 DESCRIPTION

This class encapsulates a bitcoin transaction.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
