#!/usr/bin/perl
package Bitcoin::Database;
use v5.14;
use strict;
use warnings;

use constant DATA_DIR => $ENV{HOME}.'/.bitcoin';

use BerkeleyDB;
# we have to to the following to avoid some annoying warnings from BerkeleyDB
END { undef $BerkeleyDB::Term::Env; undef $BerkeleyDB::Term::Db }
END { undef $BerkeleyDB::Term::Env; undef $BerkeleyDB::Term::Db }

our ($blkindex, %blkindex);
END { undef $blkindex, untie %blkindex if defined $blkindex }

our $Env = new BerkeleyDB::Env  
    -Home => DATA_DIR,
    -Flags => DB_CREATE| DB_INIT_LOCK| DB_INIT_LOG| DB_INIT_MPOOL| DB_INIT_TXN| DB_THREAD| DB_RECOVER
;

sub import {
    my $pkg = shift;
    if (@_ < 1) { return }
    elsif (@_ == 1 and $_[0] eq ':all') { $pkg->import( qw(blkindex) ) }
    else {
	use Perl6::Junction qw(none);
	for (@_) {
	    next if $_ eq none qw(blkindex);
	    unless (defined $blkindex) {
		$blkindex = tie %blkindex, 'BerkeleyDB::Btree',
		-Filename => $_.'.dat',
		-Subname  => 'main',
		-Env      => $Env,
		-Flags    => DB_THREAD| DB_RDONLY,
		    or warn "could not tie $_.dat: $!"
		;
	    }
	}
    }
}

1;


__END__

=head1 TITLE

Bitcoin::Database

=head1 SYNOPSIS

    use Bitcoin::Database;

=head1 DESCRIPTION

This modules provides database environnement for opening bitcoin database created by the vanilla client.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
