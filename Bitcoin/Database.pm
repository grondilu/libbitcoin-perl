package Bitcoin::Database;
require Bitcoin::Database::SQL;
our @ISA = 'Bitcoin::Database::SQL';

1;

__END__

=head1 TITLE

Bitcoin::Database

=head1 SYNOPSIS

    use Bitcoin::Database;

=head1 DESCRIPTION

This module is a wrapper for a specific implementation.  It inherits either from:

- Bitcoin::Database::SQL
- Bitcoin::Database::Berkeley
- Bitcoin::Database::Storable

=cut
