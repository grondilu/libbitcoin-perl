#!/usr/bin/perl -w
package Bitcoin::Electrum;
@ISA = qw(Exporter);
@EXPORT_OK = qw(SERVER_LIST DEFAULT_PORT py2json json2py);
use strict;

use constant COMMANDS = qw(
help
validateaddress
balance
contacts
create
payto
sendtx
password
newaddress
addresses
history
label
gui
mktxseedt2
);

use constant DEFAULT => {
    GAP_LIMIT => 5,
    PORT => 50000,
    SERVER_LIST => [ qw(
	ecdsa.org
	electrum.novit.ro
	)
    ],
    FEE => 0.005,
};

# Electrum server communicates with clients using python syntax (sic),
# so we'll use home made translators, using JSON as a bridge.

sub py2json {
    my $python = shift;
    return qx{python -c 'import json; import ast; print json.dumps(ast.literal_eval( """$python""" ))' };
}

sub json2py {
    my $json = shift;
    return qx{python -c 'import json; print repr(json.loads( """$json""" ))'};
}

1;

__END__

=head1 TITLE

Bitcoin::Electrum

=head1 SYNOPSIS

use Bitcoin::Electrum qw(SERVER_LIST);

=head1 DESCRIPTION

This package contains static information about the electrum network (servers, irc channels and so on).

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
