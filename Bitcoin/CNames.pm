#!/usr/bin/perl
package Bitcoin::CNames;
# bitcoin C++ class name   <=>  perl package name
require Bitcoin::Key;
package CPrivKey;		our @ISA = qw(Bitcoin::Key::Private);
package CSecret;		our @ISA = qw(Bitcoin::Key::Secret);
package CMasterKey;		our @ISA = qw(Bitcoin::Key::MasterKey);

require Bitcoin::Base58;
package CBase58Data;		our @ISA = qw(Bitcoin::Base58::Data);

require Bitcoin::Address;
package CBitcoinAddress;	our @ISA = qw(Bitcoin::Address);

require Bitcoin::Wallet;
package CWallet;		our @ISA = qw(Bitcoin::Wallet);

require Bitcoin::KeyStore;
package CKeyStore;		our @ISA = qw(Bitcoin::KeyStore);
package CBasicKeyStore;		our @ISA = qw(Bitcoin::KeyStore::Basic);
package CCryptoKeyStore;	our @ISA = qw(Bitcoin::KeyStore::Encrypted);

require Bitcoin::Block;
package CBlock;			our @ISA = qw(Bitcoin::Block);
package CBlockIndex;		our @ISA = qw(Bitcoin::Block::Index);
package CBlockLocator;		our @ISA = qw(Bitcoin::Block::Locator);

require Bitcoin::Protocol;
package CAddress;		our @ISA = qw(Bitcoin::Network::Address);

1;

__END__

=head1 TITLE

Bitcoin::CNames

=head1 SYNOPSIS

    use Bitcoin::CNames;

    my $addr = new CBitcoinAddress "1DxH3bjYeCKbSSPECIMENBjsTcxagmWjHy";
    my $key  = new CSecret;
    ...

=head1 DESCRIPTION

This module imports all bitcoin related packages with their corresponding C++ name in the vanilla implementation.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
