-- Table "blocks" actually only contains block headers
CREATE TABLE blocks (
    hash                char(32) binary primary key,

    version             integer default 1,
    hashPrev            char(32) binary not null,
    hashMerkleRoot      char(32) binary not null,
    nTime               integer unsigned not null,
    nBits               integer unsigned not null,
    nNonce              integer unsigned not null,

    key (hashMerkleRoot),
    key (hashPrev)
);

-- We'll insert the genesis block here as some triggers won't behave well
-- with an empty 'blocks' table.
INSERT INTO blocks values (
    unhex("6FE28C0AB6F1B372C1A6A246AE63F74F931E8365E15A089C68D6190000000000"),

    1,
    unhex("0000000000000000000000000000000000000000000000000000000000000000"),
    unhex("3BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A"),
    1231006505,
    486604799,
    2083236893
);

-- A view of orphan blocks
-- (notice that we don't use any "view" prefix in the name here)
CREATE VIEW orphan_blocks AS
SELECT a.*
FROM blocks a LEFT JOIN blocks b
ON a.hashPrev = b.hash
WHERE b.hash IS NULL;

-- Merkle transaction trees are stored in their own table
CREATE TABLE Merkle_trees (
    root                char(32) binary not null,
    idx                 integer unsigned not null,
    hash		char(32) binary,
    primary key (root, idx),
    key (root)
);

-- Transactions
CREATE TABLE transactions (
    hash                char(32) binary primary key,
    version             integer,
    lockTime            integer unsigned,
);

-- Transaction inputs
CREATE TABLE tx_in (
    hash                char(32) binary,
    prevout_hash        char(32) binary,
    prevout_n           integer unsigned,
    scriptSig           blob,
    sequence            integer unsigned,

    primary key (hash, prevout_hash, prevout_n),
    key(hash)
)

-- Transaction outputs
CREATE TABLE tx_out (
    tx_out_id           integer unsigned primary key auto_increment,
    hash                char(32) binary,
    value               integer,
    scriptPubKey        blob,

    key (hash)
);

-- hashes are stored in binary so a few views are needed
-- to get a human-readable format
CREATE VIEW view_blocks AS
SELECT 
HEX(hash) as hash,
version,
HEX(hashPrev) as hashPrev,
HEX(hashMerkleRoot) as hashMerkleRoot,
nTime,
nBits,
nNonce
FROM blocks;

CREATE VIEW view_orphan_blocks AS
SELECT view_blocks.*
FROM view_blocks INNER JOIN orphan_blocks
ON view_blocks.hash = HEX(orphan_blocks.hash);

CREATE VIEW view_Merkle_trees AS
SELECT HEX(root) as root, HEX(hash) as hash, idx
FROM Merkle_trees;

-- A function to compute target from nBits
CREATE FUNCTION target (bits float)
RETURNS REAL DETERMINISTIC
RETURN mod(bits, 0x1000000) * pow( 256, bits div 0x1000000 - 3 );

-- To create the block tree structure,
-- we'll use the interval model.
-- Each node (i.e. each block) will have a left
-- and a right edge.  We must ensure that descending
-- blocks have edges inside its parent's edges.

CREATE TABLE block_tree (
    node	char(32) binary primary key,
    L           integer unsigned not null,
    R		integer unsigned not null check (R > L),
    height	integer unsigned not null
);

-- We insert the genesis node manually.
-- Left edge is 0, right edge is 1, height is 0.
INSERT INTO block_tree values (
    unhex("6FE28C0AB6F1B372C1A6A246AE63F74F931E8365E15A089C68D6190000000000"),
    0,
    1,
    0
);

CREATE TRIGGER add_block_in_tree AFTER INSERT ON blocks
FOR EACH ROW
BEGIN
    UPDATE block_tree t, block_tree r
    SET t.L=t.L+2
    WHERE r.node = new.hashPrev
    AND t.L >= r.D

    UPDATE block_tree t, block_tree r
    SET t.D=t.D+2
    WHERE r.node = new.hashPrev
    AND t.D >= r.D

    INSERT INTO block_tree (node, L, R, height)
    SELECT new.hash, r.D, r.D + 1, r.height + 1
    FROM block_tree r
    WHERE r.node = new.hashPrev
END;
