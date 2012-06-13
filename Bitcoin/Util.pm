#!/usr/bin/perl
package Bitcoin::Utils;
@ISA = qw(Bitcoin::Util);
package Bitcoin::Util;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(randInt);
use strict;
use warnings;

# random number generator
sub randInt;

# ascii <-> integer
sub atoi;
sub itoa;

# ascii <-> bytes
sub atob;
sub btoa;

# integer <-> bytes
sub itob;
sub btoi;

{
    use bigint;

    sub randInt {
	use Digest::SHA qw(sha256_hex);
	my $r = hex sha256_hex time . $$ . qx(openssl rand 32 2>&-) . qx(ps axww |gzip -f);
	my $m = shift;
	return defined $m ? $r % $m : $r;
    }

    sub atoi {
	my $_ = shift;
	die 'non ASCII string' unless /\A[[:ascii:]]+\Z/;
	my $n = 0;
	$n = 128*$n + ord $_ for reverse /(.)/g;
	return $n;
    }

    sub itoa {
	my $n = shift;
	die 'not a positive integer' unless $n =~ /\A\d+\Z/;
	my $s;
	while ($n > 0) { $s .= chr($n % 128); $n /= 128 }
	return $s;
    }

    sub itob {
	my $n = shift;
	die 'not a positive integer' unless $n =~ /\A\d+\Z/;
	my $b;
	while ($n > 0) { $b .= chr($n % 256); $n /= 256 }
	return $b;
    }

    sub btoi {
	my $_ = shift;
	my $n = 0;
	$n = 256*$n + ord $_ for reverse /(.)/gms;
	return $n;
    }

    sub btoa { itoa btoi shift }
    sub atob { itob atoi shift }

}
1;

__END__

=head1 TITLE

Bitcoin::Util

=head1 SYNOPSIS

    use Bitcoin::Util;

    my $n = Bitcoin::Util::atoi ("foo bar");
    say +Bitcoin::Util::itoa $n;

=head1 DESCRIPTION

This module gathers various utility functions not really specific to the bitcoin protocol.

=head1 AUTHOR

L Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut
