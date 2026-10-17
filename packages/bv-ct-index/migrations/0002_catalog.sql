-- bv-ct-index catalog in D1 `bv-ct-index-cursors` (binding CURSORS), US-12 contract v2 "Storage".
-- runs: one row per sorted-run R2 object (src/codec.ts). key_lo and key_hi are its smallest and largest row keys,
-- both inclusive. block_index holds serializeBlockIndex output. The TS shape is RunDescriptor (src/types.ts).
CREATE TABLE runs (
	id TEXT PRIMARY KEY,
	generation INTEGER,
	tier INTEGER CHECK (tier BETWEEN 0 AND 3),
	key_lo TEXT,
	key_hi TEXT,
	r2_key TEXT,
	rows INTEGER,
	bytes INTEGER,
	block_index BLOB,
	created_at TEXT
);

-- A read selects the runs of meta.current_generation whose [key_lo, key_hi] overlaps the queried key range.
CREATE INDEX runs_generation_tier_range ON runs (generation, tier, key_lo, key_hi);

-- Keys: current_generation, index_started_at, fresh_through.
CREATE TABLE meta (
	k TEXT PRIMARY KEY,
	v TEXT
);

-- One row per UTC day. Writers add their ops here, and killed = 1 stops the tailer and compaction (reads continue).
CREATE TABLE ops_ledger (
	day TEXT PRIMARY KEY,
	r2_class_a INTEGER,
	r2_class_b INTEGER,
	d1_rows INTEGER,
	killed INTEGER DEFAULT 0
);
