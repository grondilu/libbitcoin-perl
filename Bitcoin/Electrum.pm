#!/usr/bin/perl -w
package Bitcoin::Electrum;
use strict;

use constant COMMANDS => qw(
help validateaddress balance contacts create payto sendtx password newaddress
addresses history label gui mktxseedt2
);

use constant DEFAULT => {
    SERVERS => [ qw(
    ecdsa.org
    electrum.novit.ro
    ) ],
    PORT => 50000,
    FEE => 0.005,
};

our @server = @{DEFAULT->{SERVERS}};
our $port = DEFAULT->{PORT};
our $fee = DEFAULT->{FEE};

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

use Bitcoin::Electrum;

push @Bitcoin::Electrum::server, '192.168.0.45';
$Bitcoin::Electrum::fee = 0;

=head1 DESCRIPTION

This package contains static information about the electrum network (servers, irc channels and so on).

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
