// SPDX-License-Identifier: BUSL-1.1
/**
 * How many entries each get-entries request of an RFC 6962 log asks for. Kept per isolate in a map, so a fresh
 * isolate starts every log at RFC6962_PAGE and relearns in a visit or two.
 */

/** get-entries asks for this many entries; logs return fewer (measured 3 to 246 per page, and 32 on Google's logs). */
export const RFC6962_PAGE = 256;
/** Page size an RFC 6962 log steps down to after a timeout (a multiple of 32, which logs that cut pages cut at). */
export const STEPPED_DOWN_PAGE = 32;
/** Pages in a row that must succeed at a stepped-down size before the log is asked for RFC6962_PAGE again. */
export const STEP_UP_AFTER_PAGES = 24;
/** Each step-down that follows a step-up doubles the pages required, up to this. */
export const MAX_STEP_UP_AFTER_PAGES = 384;

interface Paging {
	/** Entries per page the log has been seen to serve when fewer than RFC6962_PAGE (a short page, then a page with entries). */
	cap: number | null;
	/** What requests ask for: RFC6962_PAGE, or STEPPED_DOWN_PAGE after a timeout. */
	limit: number;
	/** Pages in a row that succeeded while stepped down. */
	good: number;
	/** Good pages needed to step back up. */
	required: number;
	/** The log stepped back up and has not stepped down since. */
	steppedUp: boolean;
}

const paging = new Map<string, Paging>();

export function resetPaging(): void {
	paging.clear();
}

function pagingOf(logId: string): Paging {
	let entry = paging.get(logId);
	if (!entry) paging.set(logId, (entry = { cap: null, limit: RFC6962_PAGE, good: 0, required: STEP_UP_AFTER_PAGES, steppedUp: false }));
	return entry;
}

/** Entries a get-entries page asks for. */
export function pageSizeOf(logId: string): number {
	const entry = paging.get(logId);
	return entry ? Math.min(entry.cap ?? RFC6962_PAGE, entry.limit) : RFC6962_PAGE;
}

/** Whether requests are aligned to the page size: they are while the log is stepped down. */
export function isAligned(logId: string): boolean {
	return (paging.get(logId)?.limit ?? RFC6962_PAGE) < RFC6962_PAGE;
}

/**
 * Step-down rule: a timeout, or a short page that ends on a 32-entry boundary (the log cuts requests there), drops the
 * log from RFC6962_PAGE to STEPPED_DOWN_PAGE, and its requests are then aligned to that size. STEP_UP_AFTER_PAGES
 * successful pages in a row bring RFC6962_PAGE back; a step-down right after a step-up doubles that number (to
 * MAX_STEP_UP_AFTER_PAGES), so a log that cannot serve the big page is not asked for it every few windows.
 */
export function stepDown(logId: string): void {
	const entry = pagingOf(logId);
	if (entry.steppedUp) entry.required = Math.min(entry.required * 2, MAX_STEP_UP_AFTER_PAGES);
	entry.steppedUp = false;
	entry.limit = STEPPED_DOWN_PAGE;
	entry.good = 0;
}

/** A failed or empty page breaks consecutive success at either size without changing the learned limits. */
export function pageInterrupted(logId: string): void {
	const entry = paging.get(logId);
	if (entry) entry.good = 0;
}

/** A page of the log came back with entries. */
export function pageServed(logId: string): void {
	const entry = paging.get(logId);
	if (!entry) return;
	if (entry.limit >= RFC6962_PAGE) {
		// Back at the full size and holding: after STEP_UP_AFTER_PAGES good pages the doubled requirement is forgotten, so
		// an occasional timeout on a healthy log does not ratchet it towards MAX_STEP_UP_AFTER_PAGES for the isolate's life.
		if (entry.steppedUp && ++entry.good >= STEP_UP_AFTER_PAGES) {
			entry.steppedUp = false;
			entry.required = STEP_UP_AFTER_PAGES;
			entry.good = 0;
		}
		return;
	}
	if (++entry.good >= entry.required) {
		entry.limit = RFC6962_PAGE;
		entry.good = 0;
		entry.steppedUp = true;
	}
}

/** The log serves `entries` per page whatever is asked for. */
export function learnCap(logId: string, entries: number): void {
	pagingOf(logId).cap = entries;
}
