CREATE TABLE block (
    hash char(32) binary primary key,

    version	integer,
    hashPrev		char(32) binary not null,
    hashMerkleRoot	char(32) binary not null,
    nTime	integer unsigned not null,
    nBits	integer unsigned not null,
    nNonce      integer unsigned not null,

    work	float   unsigned,
    depth	integer unsigned,

    key (hashMerkleRoot),
    key (hashPrev)
    key (depth)
);

CREATE TABLE transaction (
    hash char(32) binary primary key,
    version integer,
    lockTime integer unsigned,
    coinbase boolean
);

CREATE TABLE Merkle_tree (
    root char(32) unsigned not null,
    idx  integer unsigned,
    primary key (root, idx),
    key (root)
);

CREATE VIEW view_block AS
SELECT 
HEX(hash) as hash,
version,
HEX(hashPrev) as hashPrev,
HEX(hashMerkleRoot) as hashMerkleRoot,
nTime,
nBits,
nNonce,
work,
depth
FROM block;

