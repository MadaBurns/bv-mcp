// SPDX-License-Identifier: BUSL-1.1
/** Types of the bounded catch-up reader (src/tailer/catchup.ts, which documents the design). */

export interface BackfillRow {
	log_id: string;
	kind: 'rfc6962' | 'static';
	url: string;
	next_index: number;
	upper_index: number;
	page_size: number | null;
}

/** One dispatch message on the catch-up queue: run the catch-up reader on this row. */
export interface CatchupRequest {
	kind: 'catchup';
	scheduledTime: number;
	logId: string;
	upperIndex: number;
}

export interface CatchupOptions {
	/** Clock for the expiry test, timestamps, leases and the ledger day. Defaults to Date.now(). */
	now?: number;
	/** Outbound fetch. Defaults to the global fetch; tests inject a fake. */
	fetch?: typeof fetch;
	/** Overrides CATCHUP_MAX_FETCHES (and the env var). */
	maxFetches?: number;
	/** Overrides CATCHUP_MAX_ENTRIES (and the env var). */
	maxEntries?: number;
	/** Overrides CATCHUP_PAGES_IN_FLIGHT (and the env var). */
	pagesInFlight?: number;
	/** Overrides CATCHUP_PHASE_MS. */
	phaseMs?: number;
	/** How often a row's read re-reads the kill switches (default KILL_RECHECK_MS). */
	killRecheckMs?: number;
	fetchTimeoutMs?: number;
	/** Overrides FLUSH_ROWS. */
	flushRows?: number;
	/** Entries asked per get-entries page; defaults to the row's page_size, then to RFC6962_PAGE. */
	pageSize?: number;
	/** Reads this row only (a dispatch message); without it, the first claimable row. */
	only?: { logId: string; upperIndex: number };
}

/** What one row's read measured, for the run's log line. */
export interface RowStats {
	logId: string;
	entries: number;
	/** Requests started. */
	fetches: number;
	/** Pages that completed, and their latency (request start to body read) in ms. */
	pages: number;
	medianMs: number | null;
	maxMs: number | null;
	timeouts: number;
	rateLimited: number;
	/** Non-2xx replies other than 429. */
	httpErrors: number;
	/** Deferrals other than 429: an empty page, a tile not served yet. */
	deferrals: number;
}

export interface CatchupSummary {
	killed: boolean;
	/** Rows this run read: 0 or 1 (a row another run holds, or one backing off, is not read). */
	rows: number;
	/** Rows that reached their ceiling this run. */
	done: number;
	entries: number;
	precerts: number;
	/** Certificates dropped because notAfter was already past; not queued. */
	expired: number;
	badEntries: number;
	badNames: number;
	noApex: number;
	names: number;
	siblings: number;
	batches: number;
	subrequests: number;
	d1Rows: number;
	/** Rows whose cursor an overlapping run had already moved. */
	lost: number;
	/** Rows another run held, so this one did not read them. */
	held: number;
	perRow: RowStats[];
	/** log_id -> error, for the rows that recorded one. */
	errors: Record<string, string>;
	/** log_id -> why its read ended early without an error. */
	deferred: Record<string, string>;
}
