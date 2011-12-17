#!/usr/bin/perl -w
package Bitcoin::Electrum::Wallet;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = ();

use Digest::SHA qw(sha256 sha256_hex);

use DB_File;

use Bitcoin;

our ($wallet, %wallet, %wallet_info, $path, @address) = {};

$SIG{$_} = sub { die 'caught signal ', shift }  for qw(INT TERM HUP);
END { undef $wallet, untie %wallet if $wallet }

use constant VERSION => 2;
use constant TEMPLATE => {
    version => VERSION,
    use_encryption => 0,
    change => {},	# index of addresses used as change
    status => {},	# current status of addresses
    history => [],
    labels => {},	# labels for addresses and transactions
    addressbook => {},	# outgoing addresses, for payments
    blocks => 0, 
};

sub passwdToCipher {
    use Crypt::Rijndael;
    new Crypt::Rijndael sha256 sha256 shift || 'dummy password';
}

sub new_seed {
    use bigint;
    my $seed = hex sha256_hex join rand, map sha256($_),
    time ^ $$ , qx({ ps axww; dmesg; ls -l /tmp; }|gzip -f);
    return $seed % 2**128;
}

sub wallet_dir {
    my $wallet_dir =
    exists $ENV{HOME} ?			$ENV{HOME}		.'/.perlectrum' :
    exists $ENV{LOCALAPPDATA} ?		$ENV{LOCALAPPDATA}	.'/Perlectrum' :
    exists $ENV{APPDATA} ?		$ENV{APPDATA}		.'/Perlectrum' :
    die q{could not find appropriate application directory};
    mkdir $wallet_dir unless -d $wallet_dir;
    return $wallet_dir;
}

sub create_new_address {

    my $password = shift;
    my $for_change = shift;
    my $cipher = passwdToCipher($password);
    my $seed = eval { $cipher->decrypt($wallet->{seed}) };
    die $@ if $@;

    # strenghtening seed
    my $oldseed = $seed;
    $seed = sha512 $seed . $oldseed for 1 .. 100_000;

    # finalizing seed
    my $change = keys %{$wallet->{change}};
    my $i = $for_change ? $change : keys(%{$wallet->{addresses}}) - $change;
    $seed = sprintf "%d:%d:%s", $i, $for_change ? 'change' : '', $seed;

    # creating secret exponant
    use bigint;
    my $secexp = hex sha256_hex sha256 $seed;
    srand $secexp % 2**32;
    $secexp = 256 * $secexp + int rand 256 for 1 .. 32;
    use EC::Curves qw(secp256k1);
    $secexp %= secp256k1->{G}[2];

    # computing public point
    use EC;
    EC::init map secp256k1->{$_}, qw( p a b );
    my $public_point = EC::mult $secexp, secp256k1->{G};

    # converting into bitcoin address
    my $address = new Bitcoin::Address pack 'H40',
    Bitcoin::Hash160 chr(4) . pack 'H64H64', map &int_to_hex, @$public_point[0,1];

    # encrypting exponant and storing in database
    $wallet{$$address} = $cipher->encrypt( (2**256+$secexp)->as_hex =~ s/0x1//r );
    $wallet_info->{change}{$$address}++ if $for_change;

    return $address;
}

sub recover {
    my $password = shift;
    my $cipher = passwdToCipher($password);
    ...
}

sub save {
    die "$path is not writtable" if -f $path and not -w $path;
    die "nothing to save" unless %$wallet;
    store $wallet, $path;
}

sub is_mine {
    my $addr = shift;
    $addr = $$addr if ref $addr eq 'Bitcoin::Address';
    return exists $_->{addresses}{$addr};
}
sub is_change {
    my $addr = shift;
    die "given address is not even in wallet" unless $_->is_mine($addr);
    return exists $_->{change}{$addr};
}

sub get_new_address {
    ...
}

1;

__END__

=head1 TITLE

Bitcoin::Electrum::Wallet

=head1 SYNOPSIS

    use Bitcoin::Electrum::Wallet;

    my $wallet = load Bitcoin::Electrum::Wallet "$ENV{HOME}/.electrum/electrum.dat";

    print $wallet->version, "\n";
    print $wallet->path, "\n";
    print $_, "\n" for keys %{$$wallet{addresses}};

=head1 DESCRIPTION

This class implements a wallet used by an Electrum client.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
