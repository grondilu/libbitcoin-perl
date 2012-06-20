CREATE TABLE block (
    hash                char(32) binary primary key,

    version             integer,
    hashPrev            char(32) binary not null,
    hashMerkleRoot      char(32) binary not null,
    nTime               integer unsigned not null,
    nBits               integer unsigned not null,
    nNonce              integer unsigned not null,

    key (hashMerkleRoot),
    key (hashPrev)
);

CREATE TABLE transaction (
    hash                char(32) binary primary key,
    version             integer,
    lockTime            integer unsigned,
);

CREATE TABLE tx_in (
    hash                char(32) binary,
    prevout_hash        char(32) binary,
    prevout_n           integer unsigned,
    scriptSig           blob,
    sequence            integer unsigned,

    primary key (hash, prevout_hash, prevout_n),
    key(hash)
)

CREATE TABLE tx_out (
    tx_out_id           integer unsigned primary key auto_increment,
    hash                char(32) binary,
    value               integer,
    scriptPubKey        blob,

    key (hash)
);

CREATE TABLE Merkle_tree (
    root                char(32) binary not null,
    hash		char(32) binary,
    idx                 integer unsigned not null,
    primary key (root, idx),
    key (root)
);

CREATE TABLE chain (
    hash        char(32) binary,
    parent      char(32) binary,
    distance    integer unsigned,
    work        float ,
    PRIMARY KEY (hash, parent)
);

CREATE VIEW view_block AS
SELECT 
HEX(hash) as hash,
version,
HEX(hashPrev) as hashPrev,
HEX(hashMerkleRoot) as hashMerkleRoot,
nTime,
nBits,
nNonce
FROM block;

CREATE VIEW view_merkle_tree AS
SELECT
HEX(root) as root,
HEX(hash) as hash,
idx
FROM Merkle_tree;

CREATE VIEW view_chain AS
SELECT
HEX(hash) as hash,
HEX(parent) as parent,
distance,
work
FROM chain;

CREATE FUNCTION target (bits float)
RETURNS REAL DETERMINISTIC
RETURN mod(bits, 0x1000000) * pow( 256, bits div 0x1000000 - 3 );

CREATE TRIGGER trigger_chain BEFORE INSERT ON block 
FOR EACH ROW BEGIN
    SET @newWork = 256 - log2(target(new.nBits));
    INSERT INTO chain (hash, parent, distance, work)
    SELECT new.hash, new.hash, 0, @newWork;

    INSERT INTO chain (hash, parent, distance, work)
    SELECT new.hash, parent, distance + 1, work + @newWork
    FROM chain WHERE hash = new.hashPrev;
END;

# vim: ft=mysql
