use strict;
use Test;

BEGIN { plan tests => 8 }

use Bitcoin::Wallet;

use constant {
    address => '15gR9zUv3YW6DRf9fVvPXC7x9csPM8QcTg',
    WIF => '5JZDTbbezKW7dZcfo5auX8koqGzcJV5kA7MiehxxeMZnZvev8Dy',
    PEM => <<EOF
-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIGF5sspCOHUUAGf4C151UAX3/8FG7dui5jOBflx86WSjoAcGBSuBBAAK
oUQDQgAEg/kE+E72DbB6yuHh8ge1FperHOHDahjPzuXEz1/JZ00Qt3wJQQwUC0W9
7INs0AnqUgxwMyO5JL1TKOf1vP0Zbw==
-----END EC PRIVATE KEY-----
EOF
};

tie my %w, 'Bitcoin::Wallet', 'dummy password' or die;
END { untie %w }

$w{+address} = WIF;
ok $w{+address}, WIF;

