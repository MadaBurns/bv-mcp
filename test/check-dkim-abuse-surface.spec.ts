// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM record abuse-surface checks — the record-hygiene signals that sit past
 * "a selector with a usable key exists".
 *
 * Scope note: DKIM *replay* (re-sending a validly-signed message to new recipients to
 * borrow the signer's reputation) is mitigated by the `x=` signature-expiry tag and
 * worsened by the `l=` body-length tag — but both are per-MESSAGE DKIM-Signature HEADER
 * tags, not DNS TXT record tags (RFC 6376 §3.5 vs §3.6.1). They are structurally invisible
 * to a passive DNS scanner, so nothing here reads them. See `dkim-record-hygiene.test.ts`
 * for the pure-parser coverage.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { scoreIndicatesMissingControl } from '../src/lib/scoring';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** A ~4096-bit-length key body: long enough that analyzeKeyStrength returns `info`, so
 *  key-strength findings never pollute these record-hygiene assertions. */
const STRONG_KEY = 'A'.repeat(600);

/**
 * Mock DKIM TXT lookups for `<selector>._domainkey.example.com`.
 * CNAME probes deliberately answer empty so SaaS attribution (`delegatedTo`) stays out
 * of these assertions — the abuse-surface findings are what is under test, not attribution.
 */
function mockDkim(selectorRecords: Record<string, string[]>, domain = 'example.com') {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const params = new URL(url).searchParams;
		const queriedName = params.get('name') ?? '';
		const queriedType = params.get('type') ?? 'TXT';

		if (queriedType === 'CNAME') {
			return Promise.resolve(createDohResponse([{ name: queriedName, type: RecordType.CNAME }], []));
		}

		const selector = Object.keys(selectorRecords).find((sel) => queriedName === `${sel}._domainkey.${domain}`);
		const answers = (selector ? selectorRecords[selector] : []).map((data) => ({
			name: queriedName,
			type: RecordType.TXT,
			TTL: 300,
			data: `"${data}"`,
		}));
		return Promise.resolve(createDohResponse([{ name: queriedName, type: RecordType.TXT }], answers));
	});
}

async function runSelector(record: string | string[], selector = 'sel') {
	const { checkDkim } = await import('../src/tools/check-dkim');
	mockDkim({ [selector]: Array.isArray(record) ? record : [record] });
	return checkDkim('example.com', selector);
}

describe('DKIM t= flag parsing', () => {
	it('detects test mode when t=y is not the first flag (t=s:y)', async () => {
		// RFC 6376 §3.6.1 makes t= an unordered colon-separated list. The previous
		// substring scan (/t=y/) saw `t=y:s` but silently missed `t=s:y`.
		const r = await runSelector(`v=DKIM1; k=rsa; t=s:y; p=${STRONG_KEY}`);
		expect(r.findings.some((f) => f.title.includes('testing mode'))).toBe(true);
	});

	it('detects test mode across whitespace around the tag', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; t = y ; p=${STRONG_KEY}`);
		expect(r.findings.some((f) => f.title.includes('testing mode'))).toBe(true);
	});

	it('still detects the plain t=y form', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; t=y; p=${STRONG_KEY}`);
		const f = r.findings.find((x) => x.title.includes('testing mode'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('does not fire on a t=y substring inside the free-text n= notes tag', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; n=remove t=y after rollout; p=${STRONG_KEY}`);
		expect(r.findings.some((f) => f.title.includes('testing mode'))).toBe(false);
	});

	it('does not treat t=s (strict subdomain) as test mode', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; t=s; p=${STRONG_KEY}`);
		expect(r.findings.some((f) => f.title.includes('testing mode'))).toBe(false);
	});
});

describe('DKIM h= hash restriction', () => {
	it('keeps the high-severity sha1-only finding (RFC 8301 §3.1)', async () => {
		const r = await runSelector(`v=DKIM1; h=sha1; k=rsa; p=${STRONG_KEY}`);
		const f = r.findings.find((x) => x.title.includes('Deprecated hash algorithm'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('flags a restriction that omits sha256 entirely (h=sha512)', async () => {
		const r = await runSelector(`v=DKIM1; h=sha512; k=rsa; p=${STRONG_KEY}`);
		const f = r.findings.find((x) => x.title.includes('Hash restriction excludes SHA-256'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.metadata?.hashAlgorithms).toEqual(['sha512']);
	});

	it('flags sha1 permitted alongside sha256 as a downgrade surface', async () => {
		const r = await runSelector(`v=DKIM1; h=sha256:sha1; k=rsa; p=${STRONG_KEY}`);
		const f = r.findings.find((x) => x.title.includes('SHA-1 permitted alongside SHA-256'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		// Not ALSO reported as sha1-only — the three h= shapes are mutually exclusive.
		expect(r.findings.some((x) => x.title.includes('Deprecated hash algorithm'))).toBe(false);
	});

	it('stays silent on a healthy h=sha256 restriction', async () => {
		const r = await runSelector(`v=DKIM1; h=sha256; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => /hash|SHA-1|SHA-256/i.test(x.title))).toBe(false);
	});

	it('stays silent when h= is absent', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => /hash|SHA-1|SHA-256/i.test(x.title))).toBe(false);
	});
});

describe('DKIM s= service-type restriction', () => {
	it('flags a service list that admits neither email nor the wildcard', async () => {
		const r = await runSelector(`v=DKIM1; s=web; k=rsa; p=${STRONG_KEY}`);
		const f = r.findings.find((x) => x.title.includes('Service type excludes email'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.metadata?.serviceTypes).toEqual(['web']);
	});

	it('stays silent on s=email', async () => {
		const r = await runSelector(`v=DKIM1; s=email; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => x.title.includes('Service type'))).toBe(false);
	});

	it('stays silent on the s=* wildcard', async () => {
		const r = await runSelector(`v=DKIM1; s=*; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => x.title.includes('Service type'))).toBe(false);
	});

	it('stays silent when email appears anywhere in the list', async () => {
		const r = await runSelector(`v=DKIM1; s=web:email; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => x.title.includes('Service type'))).toBe(false);
	});

	it('stays silent when s= is absent (default is *)', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => x.title.includes('Service type'))).toBe(false);
	});
});

describe('DKIM multiple records at one selector', () => {
	it('flags two distinct key RRs published at the same selector', async () => {
		const r = await runSelector([`v=DKIM1; k=rsa; p=${STRONG_KEY}`, `v=DKIM1; k=rsa; p=${'B'.repeat(600)}`]);
		const f = r.findings.find((x) => x.title.includes('Multiple DKIM records at one selector'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.metadata?.recordCount).toBe(2);
	});

	it('stays silent for a single record at the selector', async () => {
		const r = await runSelector(`v=DKIM1; k=rsa; p=${STRONG_KEY}`);
		expect(r.findings.some((x) => x.title.includes('Multiple DKIM records'))).toBe(false);
	});
});

describe('DKIM abuse-surface findings respect the confidence model', () => {
	// A selector discovered by probing is HEURISTIC. None of the record-hygiene findings
	// may promote a result into the deterministic/verified + high-severity + missing-control
	// shape that `scoreIndicatesMissingControl()` zeroes a Core category on.
	const cases: Array<[string, string]> = [
		['h= omits sha256', `v=DKIM1; h=sha512; k=rsa; p=${STRONG_KEY}`],
		['h= permits sha1', `v=DKIM1; h=sha256:sha1; k=rsa; p=${STRONG_KEY}`],
		['s= excludes email', `v=DKIM1; s=web; k=rsa; p=${STRONG_KEY}`],
		['t=s:y test mode', `v=DKIM1; t=s:y; k=rsa; p=${STRONG_KEY}`],
	];

	for (const [name, record] of cases) {
		it(`does not zero the category for: ${name}`, async () => {
			const r = await runSelector(record);
			expect(scoreIndicatesMissingControl(r.findings)).toBe(false);
			expect(r.score).toBeGreaterThan(0);
			// An observed active key is still an observed active key.
			expect(r.controlPresent).toBe(true);
		});
	}

	it('does not zero the category for multiple records at one selector', async () => {
		const r = await runSelector([`v=DKIM1; k=rsa; p=${STRONG_KEY}`, `v=DKIM1; k=rsa; p=${'B'.repeat(600)}`]);
		expect(scoreIndicatesMissingControl(r.findings)).toBe(false);
		expect(r.score).toBeGreaterThan(0);
	});

	it('leaves the heuristic probe-miss path untouched', async () => {
		const { checkDkim } = await import('../src/tools/check-dkim');
		mockDkim({});
		const r = await checkDkim('example.com');
		expect(scoreIndicatesMissingControl(r.findings)).toBe(false);
		expect(r.score).toBe(50);
	});
});
