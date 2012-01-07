use strict;
use Test;

BEGIN { plan tests => 40 }

use Bitcoin::PrivateKey;
use Bitcoin::Address;

for (<DATA>) {
    next if /^#/;
    chomp;
    my ($i, $addr, $key) = split ',';

    $key = new Bitcoin::PrivateKey $key;
    ok( $key->address, $addr, "failed to convert WIF to bitcoin Address" );

    my $before = $key->value;
    $key->encrypt('pass');
    ok( $key->decrypt('pass')->value, $before, 'inconsistent encryption/decryption' );
}

__DATA__
# The following keys were created using javascript code on bitaddress.org
1,16PRgUZvCneM7AYJ94TaoGE4rMQnRdqqt4,5JkYWudPXkXHkmayfUz52WsweFpY7saT4V9vh4ZNtWgFLLwNgej
2,1KDxAxej4NZMQtao9xZGiadbsqxcKJt9Ng,5J4G4vaBCiAF881AMEEyc8uC2EHgLfCFP4BL97EvD5vnH99yC6p
3,1PnA88ck7hGSsSqpPXhaVbWL3suWXEqfsF,5KKGiz5ViCpSXzWCm9ff48g5AdK54FR3w1ByrhQDb1U6kgjmgr2
4,12jXM28Awqgm2NPgiD6EVjZmih66U5mUAt,5JfTp8uzBFzcJWhjrb7wJfevehwjT6c3WCBcYivpoRcjaSAgHtZ
5,1BV1GXQmBKF6v6CqUjH6y95KNXqtCoLNWH,5JGcHNTEqrYGVuE2sRw2Ys26xY51ypm4c1dnfZGyw8naAUjkdGM
6,1AsCoc5UVkHcfFRXUA2YtDJbse7k6Ws4Pz,5J3fMYfP7knUYk67eETrQcby9vhUHjdH9mz5Veag4TvuhX9JMnF
7,1MNJYvW6AmRhsrr9ELo5A4mRw2P4yafVZQ,5JEwVA4ek7Kcm23oPKaJEx6dj9G9UcM6DCybSb3hhaG8875L3hb
8,1HCMAqVqJEYNq444ecHeYJ235soup8wUKb,5KVZt4CfaBhPHaJ9Bw9b9zoM7TfnPBTwz3SyYBcn2fEdwHfrzJF
9,1tkf9nKFNqqD5FNyxU6C4CFBtk8dQFFLw,5JQvrDNPZeLN78jYPpscv3x15pgqDDdkMBwjzva3PMCBagop2yA
10,1NwuhznLyRaQ7e3hWpFveMVimsH5FfdhLa,5K2dPvJfj2MUvfi5zGxPvUupqPVR2o6PqEtsHzfVPregUoYKUBE
