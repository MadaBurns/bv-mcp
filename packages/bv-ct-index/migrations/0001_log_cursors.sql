-- bv-ct-index D1 `bv-ct-index-cursors` (binding CURSORS): one tailer cursor per CT log (US-12 contract, Architecture 1).
-- kind: 'rfc6962' reads get-sth + get-entries; 'static' reads a static-ct checkpoint + data tiles.
-- next_index is the next leaf index to fetch; tree_size is the last observed tree size.
CREATE TABLE log_cursors (
	log_id TEXT PRIMARY KEY,
	kind TEXT CHECK (kind IN ('rfc6962', 'static')),
	url TEXT,
	next_index INTEGER,
	tree_size INTEGER,
	updated_at TEXT
);
