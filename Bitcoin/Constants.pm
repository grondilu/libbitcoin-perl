package Bitcoin::Constants;

BEGIN {
    $ENV{BITCOIN_TEST} //= 'yes';
    $ENV{BITCOIN_MAGIC} //= 'yes';
}

use constant {
    
    THIS_IS_TEST => lc $ENV{BITCOIN_TEST} ~~ [ qw( yes 1 true ) ] ? 1 : 0,
    MAGIC        => lc $ENV{BITCOIN_MAGIC} ~~ [ qw( yes 1 true ) ] ? 1 : 0,
    
    DATA_DIR     => $ENV{BITCOIN_DATA_DIR} //= $ENV{HOME} .
    (THIS_IS_TEST ? "/.bitcoin/testnet" : "/.bitcoin"),
    
    GENESIS => THIS_IS_TEST ?
    '00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008' :
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    
    MESSAGE_START => THIS_IS_TEST ? 0xDAB5BFFA : 0xD9B4BEF9,

    CHECKPOINTS => [ qw(
	0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d
	000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6
	0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20
	00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97
	00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe
	000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763
	00000000000002334c71b8706940c20348af897a9cfc0f1a6dab0d14d4ceb815
	)
    ],

    DEFAULT_PORT => THIS_IS_TEST ? 18333 : 8333,

    IRC => {
	SERVER => 'irc.lfnet.org',
	PORT => 6667,
	CHANNEL => THIS_IS_TEST ? 'bitcoinTEST' : 'bitcoin',
    },

};

CHECK { DATA_DIR or die "undefined data dir" }
CHECK { -d DATA_DIR and -x DATA_DIR
	or die DATA_DIR . " does not exist or is not writable. Exiting"
}

1;
