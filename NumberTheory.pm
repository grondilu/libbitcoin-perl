#!/usr/bin/perl
package NumberTheory;
require 5.014_002;
require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(dc inverse_mod);

use strict;
use warnings;
use integer;

our $method = 'dc';
use constant DC_REGISTERS => '
[ # modular inverse ( x m -- y )
    dsm+ sc lmsd
    1su 0sv  0sr 1st
    [
	ldlc~ lc                   sd sc sq
	lrlqlu*- ltlqlv*- lu lv    st sr sv su
	lc0!=X
    ]sX
    lc0!=X
    lr 
    [lm+]s+ d0>+
]sI
';

sub dc {
    # dc wrapper
    open my $dc, '-|', qw(dc -e),
    DC_REGISTERS.
    join ' ', map s/^-/_/r, @_;
    return join '', map s/\\\n//r, <$dc>;
}

sub inverse_mod {
    for ( $method ) {
	if ( /^dc$/i ) { return new Math::BigInt dc @_, "lIx n" }
	else {
	    use bigint;

	    my ($a, $m) = @_;
	    $a %= $m if $a < 0 or $m <= $a;
	    my ($c, $d) = ($a, $m);
	    my ($uc, $vc, $ud, $vd) = (1, 0, 0, 1);
	    my $q;
	    while ($c != 0) {
		($q, $c, $d) = ($d/$c, $d%$c, $c);
		($uc, $vc, $ud, $vd) = ($ud - $q*$uc, $vd - $q*$vc, $uc, $vc);
	    }
	    return $ud < 0 ? $ud + $m : $ud;
	}
    }
}

1;


__END__

=head1 NAME

NumberTheory

=head1 SYNOPSIS

    use NumberTheory qw(inverse_mod);

    use bigint;
    $mersenne_prime = 2**61 - 1;
    $i = inverse_mod 31, $mersenne_prime;

    print $i * 31 % $p;

    $NumberTheory::method = 'simple';

    $i = inverse_mod 31, 49;

=head1 DESCRIPTION

This module mainly implements the modular inverse algorithm.

=head1 WARNINGS

=head2 Default method is 'DC'

It appeared to be much faster to use dc, the unix Desktop Calculator, rather
than Math::BigInt, even with the 'GMP' library.  Therefore, using dc is the
default computing method.

You must set $NumberTheory::method to anything but 'dc' if dc is not installed
on your system.

=head2 Watch for non prime power modulo

Normally the modular inverse is ensured to exist only if the modulo is a prime
power, but the implemented algorithm does not check for that.

=head1 BUGS

They may exist, but none is known so far.

=head1 AUTHOR

L. Grondin <grondilu@yahoo.fr>

=head1 COPYRIGHT AND LICENSE

Copyright 2011, Lucien Grondin.  All rights reserved.  

This library is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself (L<perlgpl>, L<perlartistic>).

=cut

