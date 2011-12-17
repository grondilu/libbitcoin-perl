#!/usr/bin/perl -w
package Bitcoin::Electrum;
@ISA = qw(Exporter);
@EXPORT_OK = qw(SERVER_LIST DEFAULT_PORT);
use strict;

use constant {
    DEFAULT_PORT => 50000,
    SERVER_LIST => [ qw(
	ecdsa.org
	electrum.novit.ro
	)
    ],
};

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
