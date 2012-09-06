package Bitcoin::Constants;

use constant DATA_DIR => $ENV{BITCOIN_DATA_DIR};
use constant GENESIS => '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

CHECK { DATA_DIR or die "undefined data dir" }
1;
