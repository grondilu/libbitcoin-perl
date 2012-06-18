package Bitcoin::Database::SQL;
use DBI;
use strict;
use warnings;

our $dbh = DBI->connect('dbi:mysql:bitcoin', undef, undef);
END { $dbh->disconnect; }

package Bitcoin::Block;
sub load {
    my $this = shift;
    if( ref $this ) { ref($this)->load($this->header->get_hash) }
    else {
	my $hash = shift;
	$hash = pack 'H*', $hash if $hash =~ /\A[[:xdigit:]]{64}\z/;
	my $sth = $Bitcoin::Database::SQL::dbh->prepare(
	    q{ select * from block where hash = ? or hash = ? }
	);
	$sth->bind_param(1, $hash);
	$sth->bind_param(2, scalar reverse $hash);
	$sth->execute;
	my $unblessed = $sth->fetchrow_hashref;
	return undef unless defined $unblessed;
	my $header = bless {
	    map { $_ => $unblessed->{$_} }
	    grep { exists $unblessed->{$_} }
	    qw(version hashPrev hashMerkleRoot nTime nBits nNonce)
	}, 'Bitcoin::Block::Header';
	my $block = {
	    map { $_ => $unblessed->{$_} }
	    grep { exists $unblessed->{$_} }
	    qw(depth work)
	};
	$block->{header} = $header;
	return bless $block, $this;
    }
}

sub save {
    my $block = shift;
    my $header = $block->header;
    my $sth = $Bitcoin::Database::SQL::dbh->prepare(
	q{
	insert ignore
	into block (hash, version, hashPrev, hashMerkleRoot, nTime, nBits, nNonce)
	values     (   ?,       ?,        ?,              ?,     ?,     ?,      ?)
	}
    );
    $sth->bind_param(1, $header->get_hash);
    $sth->bind_param(2, $header->version);
    $sth->bind_param(3, $header->hashPrev);
    $sth->bind_param(4, $header->hashMerkleRoot);
    $sth->bind_param(5, $header->nTime);
    $sth->bind_param(6, $header->nBits);
    $sth->bind_param(7, $header->nNonce);
    $sth->execute;
    return $block;
}

sub dbupdate {
    my $this = shift;
    my $sth = $Bitcoin::Database::SQL::dbh->prepare(
	q{
	update block
	set depth = ?, work = ?
	where hash = ?
	}
    );
    $sth->bind_param(1, $this->depth);
    $sth->bind_param(2, $this->work);
    $sth->bind_param(3, $this->get_hash);
    my $rc = $sth->execute;
    return $this;
}


1;

__END__

=head1 TITLE

Bitcoin::Database::SQL

=head1 SYNOPSIS

    use Bitcoin::Database::SQL;

    my $dbh = new Bitcoin::Database::SQL 'mysql';

    use Bitcoin::Block;
    $dbh->add_block(
	new Bitcoin::Block {
	    version => 0,
	    hashPrev => 0x000.......,
	    hashMerkleRoot => 0xabcdef012.......,
	    ...
	}
    );



=head1 DESCRIPTION

This module is an experimental SQL implementation of the bitcoin database.



