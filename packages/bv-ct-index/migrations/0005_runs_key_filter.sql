-- Read pruning for the runs catalog (SQ-401). Forward-only and nullable: a run written before this migration has NULL in
-- both columns, and the reader always reads it, so this must be applied before the code that writes the columns ships.
-- key_filter: the run's Bloom filter over key prefixes (src/codec.ts KEY_FILTER_VERSION). NULL = no filter.
ALTER TABLE runs ADD COLUMN key_filter BLOB;
-- key_split: the run's interval-index split key (src/codec.ts runSplitKey). NULL = not indexed.
ALTER TABLE runs ADD COLUMN key_split TEXT;
-- A read seeks (generation, split) once per trie node on its range's two ends, then key_hi or key_lo inside it
-- (src/indexer/read.ts), so it reads the catalog rows of the runs that overlap the range rather than the whole table.
CREATE INDEX runs_split_hi ON runs (generation, key_split, key_hi);
CREATE INDEX runs_split_lo ON runs (generation, key_split, key_lo);
-- Replaced by the two above: its key_lo range only bounded one side, so a read scanned every run sorting below its key.
DROP INDEX runs_generation_tier_range;
