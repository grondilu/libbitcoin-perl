#!/usr/bin/perl -w
package Bitcoin::Electrum::Client::GUI::GTK;
use Bitcoin::Electrum::Client;
use Bitcoin::Electrum::Client::GUI;

use Gtk2;
use Glib qw(TRUE FALSE);

my $mainwindow	= new Gtk2::Window;
my $mainbox	= new Gtk2::VBox;

# notebook
my $notebook	= new Gtk2::Notebook;


# status bar
my $statusbar	= new Gtk2::Statusbar;
my $statusimg	= new Gtk2::Image;
my $networkbtn	= new Gtk2::Button;

1;

__END__

=head1 TITLE

Bitcoin::Electrum::Client::GUI::GTK;

=head1 SYNOPSIS

    use Bitcoin::Electrum::Client::GUI::GTK;

    $Gtk2->main;

=head1 DESCRIPTION

This package is the Gtk2 implementation of GUI for the Perl Electrum client.


=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
