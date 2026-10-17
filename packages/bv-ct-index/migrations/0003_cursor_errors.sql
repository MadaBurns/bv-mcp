-- bv-ct-index D1 `bv-ct-index-cursors`: the tailer's last per-log error (US-12 contract v2, wave 2a).
-- A fetch failure or failed queue send in one log is recorded here and never fails the other logs. The columns are
-- not cleared on later success: the error is current while last_error_at is not older than updated_at. A row whose
-- next_index is NULL is a log whose head was never read; the tailer starts it at its current tree size once it is.
ALTER TABLE log_cursors ADD COLUMN last_error TEXT;
ALTER TABLE log_cursors ADD COLUMN last_error_at TEXT;
