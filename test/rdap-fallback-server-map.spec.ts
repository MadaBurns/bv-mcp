// SPDX-License-Identifier: BUSL-1.1

/**
 * Guards `FALLBACK_RDAP_SERVERS` against the #780 failure shape: an entry that
 * points at a host which does not exist.
 *
 * `.ai` was mapped to `https://rdap.nic.ai/`, a hostname with NO A RECORD. It
 * never answered. `probeRdap` fail-softs to `EMPTY_RDAP_PROBE`, so the result
 * was not an error but a silent `registrationDays: null` on EVERY `.ai` domain,
 * indefinitely — while `.org` and `.com` populated correctly, which is what made
 * it look like a per-TLD capability gap rather than a typo.
 *
 * The cost of that shape is why it deserves a test: `null` is indistinguishable
 * from "old domain, nothing notable" at every consumer, so the newly-registered
 * signal — the single highest-value output of lookalike triage — was dead for an
 * entire TLD and no output anywhere said so.
 *
 * ⚠️ SCOPE, stated plainly so nobody reads more coverage into this than exists:
 * the structural assertions below would NOT have caught #780. `https://rdap.nic.ai/`
 * is a perfectly well-formed https base URL — it is simply a host that does not
 * exist. Only the explicit `.ai` assertion pins the actual defect, and only for
 * that one TLD.
 *
 * The class-level guard is a periodic reconciliation against IANA's bootstrap
 * (data.iana.org/rdap/dns.json), which is the authoritative mapping this table
 * duplicates. That belongs in a scheduled/live check, not a unit test — a unit
 * test that fetches it would make the suite depend on someone else's uptime and
 * would fail closed on a network blip.
 *
 * ✅ THAT CHECK NOW EXISTS and is deliberately NOT wired into `npm test`:
 *
 *     npm run audit:rdap-fallback      # scripts/audits/rdap-fallback-reconcile.ts
 *
 * It fetches the live bootstrap and reports (a) entries whose target disagrees
 * with IANA, (b) entries whose host does not resolve — the #780 shape — and
 * (c) TLDs IANA covers that the table lacks. It exits 2 ("INCONCLUSIVE") rather
 * than green whenever the fetch or a DNS status cannot be established, so a
 * network blip can never read as an all-clear. Run it before adding or editing
 * an entry in `FALLBACK_RDAP_SERVERS`; the assertions below stay structural on
 * purpose and still cannot catch a dead host.
 */
import { describe, it, expect } from 'vitest';
import { FALLBACK_RDAP_SERVERS } from '../src/tools/check-rdap-lookup';

describe('FALLBACK_RDAP_SERVERS', () => {
	it('maps .ai to Identity Digital, not the non-resolving rdap.nic.ai (#780)', () => {
		// IANA's authoritative bootstrap (data.iana.org/rdap/dns.json) maps
		// ai → https://rdap.identitydigital.services/rdap/, same operator as
		// .io and .sh. `rdap.nic.ai` has no A record.
		expect(FALLBACK_RDAP_SERVERS.ai).toBe('https://rdap.identitydigital.services/rdap/');
		expect(FALLBACK_RDAP_SERVERS.ai).not.toMatch(/nic\.ai/);
	});

	it('pins the four entries the IANA reconciliation caught, and keeps .co absent', () => {
		// Found 2026-08-25 by `npm run audit:rdap-fallback`. Every one was the #780
		// failure — a silent `registrationDays: null` across a whole TLD — and each
		// replacement below was confirmed by a LIVE probe returning a registration
		// event, not merely by matching IANA.
		//
		// `.tech`/`.online` are the nastier variant: the old host resolved and
		// answered, it just 404s every domain in those TLDs. No DNS error, nothing
		// to notice — only a reconciliation against IANA finds that shape.
		expect(FALLBACK_RDAP_SERVERS.xyz).toBe('https://rdap.centralnic.com/xyz/');
		expect(FALLBACK_RDAP_SERVERS.tech).toBe('https://rdap.radix.host/rdap/');
		expect(FALLBACK_RDAP_SERVERS.online).toBe('https://rdap.radix.host/rdap/');
		expect(FALLBACK_RDAP_SERVERS.me).toBe('https://rdap.identitydigital.services/rdap/');

		// None of the known-dead hosts may reappear anywhere in the table. Matched
		// on the full HOST, not a substring: a bare /nic\.co/ also matches the
		// legitimate `rdap.centralnic.com`, which is exactly the false positive
		// this assertion tripped on first.
		const hosts = Object.values(FALLBACK_RDAP_SERVERS).map((u) => new URL(u).hostname);
		for (const dead of ['rdap.nic.xyz', 'rdap.nic.co', 'rdap.nic.me', 'rdap.nic.ai']) {
			expect(hosts).not.toContain(dead);
		}

		// `.co` is deliberately ABSENT: no operator serves public RDAP for it and
		// IANA does not publish it, so any entry would be a guess that fails slower
		// than no entry at all.
		expect(FALLBACK_RDAP_SERVERS.co).toBeUndefined();
	});

	it('routes .ai to the same operator as its sibling Identity Digital ccTLDs', () => {
		// A cheap cross-check: if someone edits one of these three, the odd one
		// out is visible rather than silently diverging.
		expect(FALLBACK_RDAP_SERVERS.ai).toBe(FALLBACK_RDAP_SERVERS.io);
		expect(FALLBACK_RDAP_SERVERS.ai).toBe(FALLBACK_RDAP_SERVERS.sh);
	});

	it.each(Object.entries(FALLBACK_RDAP_SERVERS))(
		'%s is a well-formed https RDAP base URL',
		(tld, url) => {
			expect(tld, 'TLD keys are bare and lowercase').toMatch(/^[a-z0-9-]+$/);
			const parsed = new URL(url);
			expect(parsed.protocol, `${tld} must be https`).toBe('https:');
			// A hostname with no dot cannot be a public RDAP server, and a trailing
			// path is required because `probeRdap` appends `domain/<name>` to it.
			expect(parsed.hostname).toContain('.');
			expect(url.endsWith('/'), `${tld} must end in / so domain/<name> appends cleanly`).toBe(true);
		},
	);
});
