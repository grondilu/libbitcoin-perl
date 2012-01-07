#!/usr/bin/perl
package Bitcoin::Database;
use strict;
use warnings;

use Bitcoin;
use constant NAMES => qw(blkindex);

use BerkeleyDB;
# we have to to the following to avoid some annoying warnings from BerkeleyDB
END { undef $BerkeleyDB::Term::Env; undef $BerkeleyDB::Term::Db }
END { undef $BerkeleyDB::Term::Env; undef $BerkeleyDB::Term::Db }

our ($blkindex, %blkindex);
END { undef $blkindex, untie %blkindex if defined $blkindex }

our $Env = new BerkeleyDB::Env  
    -Home => Bitcoin::DATA_DIR,
    -Flags => DB_CREATE| DB_INIT_LOCK| DB_INIT_LOG| DB_INIT_MPOOL| DB_INIT_TXN| DB_THREAD| DB_RECOVER,
;

sub import {
    my $pkg = shift;
    if (@_ < 1) { return }
    elsif (@_ == 1 and $_[0] eq ':all') { $pkg->import( NAMES ) }
    else {
	for my $db (@_) {
	    next unless exists { map { $_ => undef } NAMES }->{$db};
	    no strict 'refs';
	    unless (defined ${(__PACKAGE__.'::')->{$db}}) {
		${(__PACKAGE__.'::')->{$db}} = tie %{(__PACKAGE__.'::')->{$db}}, 'BerkeleyDB::Btree',
		-Filename => $db.'.dat',
		-Subname  => 'main',
		-Env      => $Env,
		-Flags    => DB_THREAD| DB_RDONLY,
		    or warn "could not tie $db.dat: $!"
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

This module is mostly for internal use, as it merely provides tools for
configuring the BerkeleyDB, but it DOES NOT parse the bitcoin-related
serialisation format.  Use Bitcoin::Block or Bitcoin::Transaction to do this.

=head2 Import mechanism

The import mechanism DOES NOT import symbols in the lexical scope as it does usually.  Instead, it is designed to select
the databases that you want to load.

    use Bitcoin::Database;                        # does not load any database
    use Bitcoin::Database qw(blkindex);           # loads the index database
    use Bitcoin::Database qw(wallet);             # loads the wallet

Once loaded, a database can be accessed using a scalar variable pointing to the BerkeleyDB object.

    $Bitcoin::Database::blkindex->db_get($k, $v, BerkeleyDB::DB_SET);

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
