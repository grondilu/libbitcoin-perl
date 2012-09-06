package Bitcoin::Database;
#use parent qw(Bitcoin::Database::SQL);
use parent qw(Bitcoin::Database::Berkeley);

1;

__END__

=head1 TITLE

Bitcoin::Database

=head1 SYNOPSIS

    use Bitcoin::Database;

    my $block = load Bitcoin::Block $blockhash;
    my $transaction = load Bitcoin::Transaction $txhash;
    my $tree = load Bitcoin::MerkleTree $treehash;

    save $block;
    save $transaction;
    save $tree;

=head1 DESCRIPTION

The perl bitcoin library doesn't allow to use several database in the same time.
However, it does allow to chose one database from several available.  This choice
must be done by inheriting Bitcoin::Database from the chosen particular package:

- Bitcoin::Database::SQL
- Bitcoin::Database::Berkeley
- Bitcoin::Database::Storable

All of these modules implement their own version of a 'save' and 'load' method
for the main Bitcoin classes:

- Bitcoin::Block
- Bitcoin::Transaction
- Bitcoin::MerkleTree

Hopefully this should allow the library user to write code that does work
on any of the available database implementations.

=cut
