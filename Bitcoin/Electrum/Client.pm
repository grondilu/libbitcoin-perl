#!/usr/bin/perl
# Perlectrum, an Electrum client in Perl :)
#
# For more info about Electrum and its original client/server in Python,
# see git://gitorious.org/electrum/electrum.py
#
# For general info about bitcoin, see http://www.bitcoin.org
#
package Bitcoin::Electrum::Client;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(gap_limit server port fee request);

use strict;
use warnings;
use Perl6::Junction qw(any all none);

# Dependencies
#
use Bitcoin;
use Bitcoin::Base58;
use Bitcoin::Address;
use Bitcoin::Electrum qw(py2perl perl2py);
use Digest::SHA qw(sha256 sha512);

# Package public variables and constants
#
our ($gap_limit, $server, $port, $fee) = (
    Bitcoin::Electrum::DEFAULT->{GAP_LIMIT},
    Bitcoin::Electrum::DEFAULT->{SERVER_LIST}[0],
    Bitcoin::Electrum::DEFAULT->{PORT},
    Bitcoin::Electrum::DEFAULT->{FEE},
);

# subroutines
#

sub raw_tx {
    my ($input, $output) = @_;
    my $for_sig = shift;

    my @tx;

    push @tx,
    [ 'version',		sprintf '%8x', 1 ],
    [ 'number of inputs',	sprintf '%8x', scalar @$input];

    for (my ($i, @input) = (0, @$input); $i < @$input; $i++) {
	my ($phash, $pindex, $pscript, $pubkey, $sig) = @input[2..6];

	my $script;
	if (not defined $for_sig) {
	    $sig .= chr(1);
	    $pubkey = chr(4) . $pubkey;
	    for ($sig, $pubkey) {
		$script = sprintf '%2x%s', length($_), unpack 'H*', $_;
	    }
	}
	elsif ($for_sig == $i) { $script = $pscript }
	else { $script = '' }

	push @tx,
	['previous hash',	unpack 'H*', reverse pack 'H*', $phash],
	['previous index',	$pindex],
	['script length',	length($script)/2],
	['script',		$script ],
	['sequence',		'ff' x 4];
    }

    push @tx, ['number of outputs', sprintf '%8x', scalar @$output];
    for (@$output) {
	my ($addr, $amount) = @$_;
	my $script = join '', '76a9', '14', substr(Bitcoin::Address::new($addr)->toHex, 2, -8), '88ac';
	push @tx,
	['amount',		sprintf '%16x', $amount];
	['script length',	length($script)/2],
	['script',		$script],
    }
    push @tx, [ 'lock time', sprintf '%8x', 0 ];
    push @tx, [ 'hash type', sprintf '%8x', 1 ] unless defined $for_sig;

    return @tx;

}

sub mktx {
    my $to_address = shift;
    my $amount = shift;
    ...
}

sub request {
    my $command = shift;
    my $response;
    if ($port == any 80, 8080, 443) {
	# We're using HTTP
	use URI;
	use URI::Escape;
	use HTTP::Tiny;
	my $uri = new URI 'http'. ($port == 443 ? 's' :''). "://ecdsa.org" ;
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
	PeerAddr	=> $server,
	PeerPort	=> $port,
	    or die "could not connect to $server:$port";
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

    use Bitcoin::Electrum::Client qw(server fee port);

    $fee = 0.01;
    $server = 'perlectrum.org';

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
