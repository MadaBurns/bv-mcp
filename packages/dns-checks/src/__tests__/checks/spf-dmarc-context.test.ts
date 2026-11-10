// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-556 item 1 — the DMARC context `checkSPF` grades its trust surface against.
 *
 * The trust-surface aggregate ("SPF trust surface: N shared platforms") escalates to `high`
 * when weak DMARC corroborates it. Before this fix the context read only `_dmarc.<scanned
 * name>` through the plain `string[]` projection, so:
 *  a. a subdomain inheriting its organisational domain's `p=reject` read as "No DMARC record
 *     is published" and was escalated, although `checkDMARC` grades the same scan as enforced;
 *  b. a SERVFAIL / REFUSED on the DMARC lookup (an empty array over HTTP 200) read as a
 *     measured absence and was escalated, although nothing was measured.
 */

import { describe, expect, it } from 'vitest';
import { checkSPF } from '../../checks/check-spf';
import type { DNSQueryFunction, Finding } from '../../types';

const RCODE_NOERROR = 0;
const RCODE_SERVFAIL = 2;
const RCODE_REFUSED = 5;

interface Answer {
	records?: string[];
	rcode?: number;
}

/** Mirror of the Worker adapter: the plain call projects to strings, `withRcode` keeps the rcode. */
function resolver(table: Record<string, Answer>): DNSQueryFunction {
	const lookup = (name: string, type: string): Answer => table[`${type} ${name}`] ?? { records: [], rcode: RCODE_NOERROR };
	const queryDNS = (async (name: string, type: string) => lookup(name, type).records ?? []) as DNSQueryFunction;
	queryDNS.withRcode = async (name: string, type: string) => {
		const answer = lookup(name, type);
		return { records: answer.records ?? [], rcode: answer.rcode ?? RCODE_NOERROR };
	};
	return queryDNS;
}

/** Three cataloged multi-tenant platforms, so the scored aggregate exists. */
const SHARED_SPF = 'v=spf1 include:_spf.google.com include:sendgrid.net include:spf.protection.outlook.com ~all';

function aggregate(findings: Finding[]): Finding {
	const finding = findings.find((f) => /^SPF trust surface: \d+ shared platforms$/.test(f.title));
	expect(finding).toBeDefined();
	return finding!;
}

function claimsDmarcMissing(findings: Finding[]): boolean {
	return findings.some((f) => /No DMARC record is published/i.test(f.detail) || f.metadata?.dmarcPolicy === 'missing');
}

describe('checkSPF trust-surface DMARC context — subdomain inheritance (RFC 9989 §4.10)', () => {
	it('reads an inherited organisational-domain p=reject on a subdomain, not "missing", and does not escalate', async () => {
		const queryDNS = resolver({
			'TXT news.example.com': { records: [SHARED_SPF] },
			'TXT _dmarc.example.com': { records: ['v=DMARC1; p=reject'] },
		});

		const result = await checkSPF('news.example.com', queryDNS);
		const summary = aggregate(result.findings);

		expect(summary.metadata?.dmarcPolicy).toBe('reject');
		expect(summary.metadata?.dmarcCorroborated).toBe(false);
		expect(summary.severity).toBe('info');
		expect(claimsDmarcMissing(result.findings)).toBe(false);
		// The ~all branch reads the same context: an inherited reject is enforcement.
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all) with DMARC enforcement')).toBe(true);
	});

	it("honours the organisational domain's sp= for the subdomain (sp=none overrides p=reject)", async () => {
		const queryDNS = resolver({
			'TXT news.example.com': { records: [SHARED_SPF] },
			'TXT _dmarc.example.com': { records: ['v=DMARC1; p=reject; sp=none'] },
		});

		const result = await checkSPF('news.example.com', queryDNS);
		const summary = aggregate(result.findings);

		expect(summary.metadata?.dmarcPolicy).toBe('none');
		expect(summary.metadata?.dmarcCorroborated).toBe(true);
		expect(summary.severity).toBe('high');
		// The per-platform findings carry the corroboration prose.
		const member = result.findings.find((f) => f.title.startsWith('SPF delegates to shared platform:'));
		expect(member?.detail).toMatch(/monitor-only \(p=none\)/);
		expect(claimsDmarcMissing(result.findings)).toBe(false);
	});
});

describe('checkSPF trust-surface DMARC context — a failed DMARC lookup is unmeasured, not missing', () => {
	it.each([
		['SERVFAIL', RCODE_SERVFAIL],
		['REFUSED', RCODE_REFUSED],
	])('%s on _dmarc.<domain> does not corroborate and does not claim DMARC is missing', async (_label, rcode) => {
		const queryDNS = resolver({
			'TXT example.com': { records: [SHARED_SPF] },
			'TXT _dmarc.example.com': { records: [], rcode },
		});

		const result = await checkSPF('example.com', queryDNS);
		const summary = aggregate(result.findings);

		expect(summary.metadata?.dmarcCorroborated).toBe(false);
		expect(summary.severity).toBe('info');
		expect(claimsDmarcMissing(result.findings)).toBe(false);
	});

	it('SERVFAIL on the organisational domain during the walk is unmeasured, not missing', async () => {
		const queryDNS = resolver({
			'TXT news.example.com': { records: [SHARED_SPF] },
			'TXT _dmarc.example.com': { records: [], rcode: RCODE_SERVFAIL },
		});

		const result = await checkSPF('news.example.com', queryDNS);
		const summary = aggregate(result.findings);

		expect(summary.metadata?.dmarcCorroborated).toBe(false);
		expect(summary.severity).toBe('info');
		expect(claimsDmarcMissing(result.findings)).toBe(false);
	});
});
