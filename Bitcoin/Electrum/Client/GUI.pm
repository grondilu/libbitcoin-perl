#!/usr/bin/perl -w
package Bitcoin::Electrum::Client::GUI;
@ISA = qw(Exporter);
@EXPORT_OK = qw(TITLE PAGES);

use Bitcoin::Electrum::Client;
use constant {
    TITLE	=> 'Perlectrum, an Electrum client in Perl',

    SETTINGS_DIALOG => {
	recovery	=>
	"Please enter your wallet seed or the corresponding mnemonic list of words, the server and the gap limit",
	create		=>
	"Please indicate the server and port number",
	default		=>
	"These are the settings of your wallet. For more explanations, click on the question mark buttons next to each input field.",
    },

};



1;

__END__

=head1 TITLE

Bitcoin::Electrum::Client::GUI

=head1 SYNOPSIS

    use Bitcoin::Electrum::Client::GUI;

=head1 DESCRIPTION

This module wraps a GUI implementation of Perlelectrum.

It gathers data that is not specific to a particular GUI toolkit.

See subpackages such as Bitcoin::Electrum::Client::GUI::Gtk2 or
Bitcoin::Electrum::Client::GUI::Tk for implementation details.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
