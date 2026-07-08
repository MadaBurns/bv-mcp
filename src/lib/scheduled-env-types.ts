// SPDX-License-Identifier: BUSL-1.1
/** Minimal standalone shape (NOT the real ScheduledEnv from src/scheduled.ts)
 * — see the Task 1 Step 3 note above for why this can't just import the real
 * type yet. Once Task 2 widens the real ScheduledEnv to a superset of this
 * shape, structural typing makes the two interchangeable at every call site. */
export interface ScheduledEnv {
	BV_WEB?: Fetcher;
	BV_WEB_INTERNAL_KEY?: string;
	SCAN_CACHE?: KVNamespace;
	ALERT_WEBHOOK_URL?: string;
}
