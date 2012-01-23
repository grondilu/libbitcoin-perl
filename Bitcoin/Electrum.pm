#!/usr/bin/perl -w
package Bitcoin::Electrum;
use Bitcoin;
use strict;

use constant SERVERS => qw(
    ecdsa.org
    electrum.novit.ro
);

use constant {
    DATA_DIR => Bitcoin::DATA_DIR . '/electrum/',
    PORT => 50000,
    FEE => 0.005,
}
;

mkdir DATA_DIR or die $! unless -d DATA_DIR;

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
