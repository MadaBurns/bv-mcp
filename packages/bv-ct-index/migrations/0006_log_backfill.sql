-- bv-ct-index D1 `bv-ct-index-cursors`: the bounded catch-up reader's work list (src/tailer/catchup.ts). One row reads the
-- range [lower_index, upper_index) of one CT log, from the row's own url and kind (so a log the Chrome list no longer
-- tails, such as a readonly one, can still be finished). It is separate from log_cursors on purpose: the forward tail's
-- compare-and-set on log_cursors is never contended by it, and a row here never changes which logs the tail follows.
-- next_index is the next leaf index to read (starts at lower_index); the reader never reads at or past upper_index and
-- sets state = 'done' when next_index reaches it. state 'paused' stops one row without the whole-reader kill switch.
-- Rows are inserted by an operator, never by a migration. The reader's own kill switch is meta k = 'catchup_killed',
-- v = '1' (the ops_ledger kill switch stops it too).
-- page_size is the entries per get-entries page the log serves: set by the reader when it sees a short page, or by the
-- operator, so every run starts with correctly aligned ranges (NULL: ask for the most the protocol allows, 256).
-- hold_until is one row's lease and back-off in one column (an ISO timestamp): a run claims the row by setting it a
-- little past its own end and clears it when done, so an overlapping run skips the row; a run that deferred (HTTP 429,
-- no entries yet) or failed sets it a few minutes ahead instead, so the row is left alone until then. The reader compares
-- it as text against an ISO-8601 time, so an operator-set value must be ISO-8601 in UTC (2026-12-01T00:00:00.000Z); the
-- CHECK rejects anything else (a value like '12/1/2026' would sort after every ISO time and hold the row for good).
CREATE TABLE log_backfill (
	log_id TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('rfc6962', 'static')),
	url TEXT NOT NULL,
	lower_index INTEGER NOT NULL,
	next_index INTEGER NOT NULL,
	upper_index INTEGER NOT NULL,
	state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'paused', 'done')),
	entries_read INTEGER NOT NULL DEFAULT 0,
	expired_skipped INTEGER NOT NULL DEFAULT 0,
	last_error TEXT,
	last_error_at TEXT,
	updated_at TEXT,
	page_size INTEGER CHECK (page_size IS NULL OR (page_size >= 1 AND page_size <= 256)),
	hold_until TEXT CHECK (hold_until IS NULL OR hold_until GLOB '????-??-??T??:??:??*Z'),
	PRIMARY KEY (log_id, upper_index),
	CHECK (lower_index >= 0 AND next_index >= lower_index AND upper_index >= next_index)
);
