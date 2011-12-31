use strict;
use warnings;
use Test;

BEGIN { plan tests => 1000 }

use NumberTheory qw(inverse_mod);

use bigint;
my $prime = 2**61 - 1;

for my $k ( 1 .. 1000 ) {
    ok inverse_mod($k, $prime) * $k % $prime, 1;
}

