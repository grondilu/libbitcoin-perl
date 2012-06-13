#!/usr/bin/perl
# Electrum client in Perl
#
# For more info about Electrum and its original client/server in Python,
# see git://gitorious.org/electrum/electrum.py
#
# For general info about bitcoin, see http://www.bitcoin.org
#
package Bitcoin::Electrum::Client;
use strict;
use warnings;

# Dependencies
#
use Bitcoin;
use Bitcoin::Base58;
use Bitcoin::Address;
use Bitcoin::Script;
use Bitcoin::Electrum qw(py2json json2py);
use Digest::SHA qw(sha256 sha512);

# Package public variables and constants
#

# subroutines
#

sub raw_tx {
    my $self = shift;
    my ($input, $output) = @_[0, 1];
    my $for_sig = shift;

    my @tx;

    push @tx,
    [ 'version',		pack 'l', 1 ],
    [ 'number of inputs',	pack 'c', scalar @$input];

    for (my $i = 0; $i < @$input; $i++) {
	my ($phash, $pindex, $pscript, $pubkey, $sig) = @{$input->[$i]}[2..6];

	my $script = 
	! defined $for_sig ?  join '', map { pack 'c1 a*', length, $_ } $sig.chr(1), chr(4).$pubkey :
	$for_sig == $i ?  pack 'H*', $pscript :
	'' ;

	push @tx,
	['previous hash',	reverse pack 'H*', $phash],
	['previous index',	pack 'l', $pindex],
	['script length',	pack 'c', length $script],
	['script',		$script ],
	['sequence',		pack 'H*', 'ff' x 4];
    }

    push @tx,
    ['number of outputs', pack 'l', scalar @$output];
    for (@$output) {
	my ($addr, $amount) = @$_;
	my $script = pack 'C C C H40 C C',
	Bitcoin::Script::Codes::OP_DUP->[0],
	Bitcoin::Script::Codes::OP_HASH160->[0],
	0x14,
	substr(Bitcoin::Address::new($addr)->toHex, 2, -8),
	Bitcoin::Script::Codes::OP_EQUALVERIFY->[0],
	Bitcoin::Script::Codes::OP_CHECKSIG->[0],
	;
	push @tx,
	['amount',		pack 'q', $amount],
	['script length',	pack 'c', length $script],
	['script',		$script],
    }
    push @tx, [ 'lock time', pack 'l', 0 ];
    push @tx, [ 'hash type', pack 'l', 1 ] unless defined $for_sig;

    return @tx;

}

sub mktx {
    my $self = shift;
    my $to_address = shift;
    my $amount = shift;
    ...
}

sub request {
    my $self = shift;
    my $command = shift;
    my $response;
    if ($Bitcoin::Electrum::port =~ /80|8080|443/) {
	# We're using HTTP
	use URI;
	use URI::Escape;
	use HTTP::Tiny;
	my $uri = new URI 'http'. ($Bitcoin::Electrum::port == 443 ? 's' :''). "://ecdsa.org" ;
	query_form $uri +{ q => $command };
	my $http_request = new HTTP::Tiny -default_headers => {
	    'Content-type'	=> 'application/x-www-form-urlencoded',
	    'Accept'		=> 'text/plain'
	};
	...
    }
    else {
	$command .= '#';
	use IO::Socket;
	my $remote = new IO::Socket::INET
	Proto		=> 'tcp',
	PeerAddr	=> $Bitcoin::Electrum::server[0],
	PeerPort	=> $Bitcoin::Electrum::port,
	    or die "could not connect to $Bitcoin::Electrum::server:$Bitcoin::Electrum::port";
	print $remote $command;
	$response = join '', <$remote>;
    }
    return $response;
}

1;

__END__

=head1 TITLE

Bitcoin::Electrum::Client

=head1 SYNOPSIS

    use Bitcoin::Electrum::Client;

    Bitcoin::Electrum::Client::load_wallet('/optionnal/path/to/your/wallet');
    Bitcoin::Electrum::Client::run();

=head1 DESCRIPTION

This module implements an Electrum's client.  It is not supposed to be used
directly.  It is rather a library designed to be used by other programs such as
GUIs.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
