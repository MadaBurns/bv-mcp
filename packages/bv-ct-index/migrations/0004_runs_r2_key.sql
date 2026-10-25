-- Garbage collection checks references across every retained generation by R2 key.
-- Without this index, every compaction cleanup scans the entire runs catalog.
CREATE INDEX runs_r2_key ON runs (r2_key);
