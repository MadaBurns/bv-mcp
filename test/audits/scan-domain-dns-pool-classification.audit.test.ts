// SPDX-License-Identifier: BUSL-1.1

/**
 * `CHECKS_WITHOUT_DNS_POOL` drift guard (#952/SQ-15 repair).
 *
 * `safeCheck`'s per-check timer extension in `src/tools/scan-domain.ts` must be
 * withheld from any `CHECK_DISPATCH` entry that ignores its 2nd (`dnsOptions`)
 * parameter — such a check never calls `dnsSemaphore.run()`, so extending its
 * deadline by the pool's queued time silently relaxes a budget nothing on that
 * check's own critical path is waiting on (the SQ-15 defect: `ssl` and
 * `http_security` kept their timeout unenforced whenever an unrelated check
 * queued on the DNS pool).
 *
 * `CHECKS_WITHOUT_DNS_POOL` is the hand-maintained classification the dispatch
 * site gates on. This test independently re-derives, from each dispatch
 * entry's OWN FUNCTION SOURCE (`Function.prototype.toString()` — the Workers
 * pool has no real filesystem, so this runs in-memory rather than reading
 * scan-domain.ts off disk), which entries discard that parameter (by the
 * repo's existing convention of prefixing an intentionally-unused parameter
 * with `_` — see the `ssl`/`http_security` entries and the CheckRunner JSDoc
 * above `CHECK_DISPATCH`) and compares the two sets directly. A new dispatch
 * entry that discards its `dns` parameter without being added to
 * `CHECKS_WITHOUT_DNS_POOL` (or vice versa) fails this test.
 */

import { describe, it, expect } from 'vitest';
import { CHECK_DISPATCH, SCAN_CATEGORIES, CHECKS_WITHOUT_DNS_POOL } from '../../src/tools/scan-domain';

/** True when `category`'s runner's 2nd parameter (the `dns`/`dnsOptions` arg) is discarded. */
function discardsDnsArg(category: string): boolean {
	const runner = CHECK_DISPATCH[category];
	if (!runner) throw new Error(`No CHECK_DISPATCH entry for "${category}" — SCAN_CATEGORIES and CHECK_DISPATCH have drifted.`);
	const source = runner.toString();
	const match = /^\(([^)]*)\)/.exec(source) ?? /^[^(]*\(([^)]*)\)/.exec(source);
	if (!match) throw new Error(`Could not parse the parameter list of the "${category}" runner from: ${source.slice(0, 80)}`);
	const params = match[1].split(',').map((p) => p.trim());
	const dnsParam = params[1];
	if (!dnsParam) throw new Error(`Runner for "${category}" has fewer than 2 parameters — expected (domain, dnsOptions, ...).`);
	return dnsParam.startsWith('_');
}

describe('scan-domain DNS-pool classification (audit)', () => {
	it('CHECKS_WITHOUT_DNS_POOL exactly matches entries that discard their dns parameter', () => {
		const actuallyDiscardsDns = SCAN_CATEGORIES.filter((cat) => discardsDnsArg(cat)).sort();
		const classified = [...CHECKS_WITHOUT_DNS_POOL].sort();

		expect(classified).toEqual(actuallyDiscardsDns);
		// ^ A mismatch means either: a new/changed dispatch entry now discards its
		//   `dns` parameter (via `_dns` or similar) without being added to
		//   CHECKS_WITHOUT_DNS_POOL — it would silently lose the #952 extension it
		//   never needed but also never explicitly opted out of, OR an entry is
		//   listed in CHECKS_WITHOUT_DNS_POOL despite actually using `dns` — it
		//   would silently lose a legitimate #952 extension it depends on.
	});

	it('sanity: the classification is exactly {ssl, http_security} today', () => {
		// Guards against the audit itself silently matching nothing (e.g. the
		// `toString()`/regex parse breaking) and passing vacuously.
		expect([...CHECKS_WITHOUT_DNS_POOL].sort()).toEqual(['http_security', 'ssl']);
	});
});
