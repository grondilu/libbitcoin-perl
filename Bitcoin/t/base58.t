use strict;

use Test;
BEGIN { plan tests => 8 }

use Bitcoin;
use Bitcoin::Base58 qw(encode decode);

ok decode('z'), 57;
ok decode('1z'), 57;
ok decode('211'), 58*58;
ok decode('2z'), 57+58;
ok encode(10), 'B';

my $r = int rand 1000;
ok decode(encode $r), $r, "consistency check failed from random integer";

use bigint;
ok decode(encode 2**20), 2**20, "consistency check failed from an integer";
ok encode(decode 'Grondi1u'), 'Grondi1u', "consistency check failed from base58 string";


ok 'Grondi1u', $Bitcoin::base58;
ok not '0Grondi1u' =~ $Bitcoin::base58;

ok encode(decode('1QAVk6rZ8Tzj6665X3v1yPGfKwNHFjGV4y')), 'QAVk6rZ8Tzj6665X3v1yPGfKwNHFjGV4y';
