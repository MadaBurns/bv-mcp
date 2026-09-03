import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, mockTxtRecords, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('validateFix', () => {
	async function run(domain: string, check: string, expected?: string) {
		const { validateFix } = await import('../src/tools/validate-fix');
		return validateFix(domain, check, expected);
	}

	it('returns fixed when check passes with no critical/high findings', async () => {
		// Simple SPF with -all and no includes avoids circular-include artifacts from the mock.
		mockTxtRecords(['v=spf1 -all']);
		const result = await run('example.com', 'spf');
		expect(result.verdict).toBe('fixed');
		expect(result.remainingFindings).toHaveLength(0);
	});

	it('returns not_fixed when critical findings remain', async () => {
		mockTxtRecords([]);
		const result = await run('example.com', 'spf');
		expect(result.verdict).toBe('not_fixed');
		expect(result.remainingFindings.length).toBeGreaterThan(0);
		expect(result.hint).toBeTruthy();
	});

	it('returns partial when check passes but has medium findings', async () => {
		// include: with the single-domain mock causes a circular include (high), so use a
		// multi-domain mock that avoids the loop. (The shared-platform trust-surface finding
		// this record also produces is informational since #637 — a single cataloged platform
		// emits no aggregate finding and is therefore unscored, so the verdict here is driven
		// by the absence of the circular-include high, not by the trust surface.)
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const name = u.searchParams.get('name') ?? '';
			const records: Record<string, string[]> = {
				'example.com': ['v=spf1 include:_spf.google.com -all'],
				'_spf.google.com': ['v=spf1 ip4:172.217.0.0/19 -all'],
				'_dmarc.example.com': [], // Missing DMARC → trust surface corroborated (info-only since #637)
			};
			const data = records[name] ?? [];
			const answers = data.map((d) => ({ name, type: 16, TTL: 300, data: `"${d}"` }));
			return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
		});
		const result = await run('example.com', 'spf');
		expect(['fixed', 'partial']).toContain(result.verdict);
	});

	it('checks expected record match', async () => {
		const expectedRecord = 'v=spf1 -all';
		mockTxtRecords([expectedRecord]);
		const result = await run('example.com', 'spf', expectedRecord);
		expect(result.expectedMatch).toBe(true);
	});

	it('reports expected record mismatch', async () => {
		mockTxtRecords(['v=spf1 ~all']);
		const result = await run('example.com', 'spf', 'v=spf1 include:_spf.google.com -all');
		expect(result.expectedMatch).toBe(false);
	});

	it('rejects unknown check names', async () => {
		await expect(run('example.com', 'nonexistent_check')).rejects.toThrow('Invalid');
	});

	it('includes live record in result', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const result = await run('example.com', 'spf');
		expect(result.liveRecord).toBeTruthy();
	});
});

/**
 * Issue #889 review — `validateFix` must not read a not-completed check's `passed: false`
 * / `score: 0` as a `not_fixed` verdict. `passed` means "did not penalize", never a verdict
 * (the #705/#706/#725/#809 class), and a scanner-side transient now returns exactly that
 * shape with `checkStatus` set. The absence of a verdict is its own value.
 */
describe('validateFix — a check that did not complete is NOT ASSESSED, not not_fixed (#889)', () => {
	async function run(domain: string, check: string) {
		const { validateFix } = await import('../src/tools/validate-fix');
		return validateFix(domain, check);
	}

	function txt(name: string, records: string[]) {
		return createDohResponse(
			[{ name, type: 16 }],
			records.map((d) => ({ name, type: 16, TTL: 300, data: `"${d}"` })),
		);
	}

	it('mta_sts with a policy fetch that throws → not_assessed, no remaining findings, hint says retry', async () => {
		// Distinct domain: check-mta-sts.ts memoizes robots.txt per hostname for the isolate.
		const domain = 'validate-not-assessed.example.com';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes(`_mta-sts.${domain}`)) return Promise.resolve(txt(`_mta-sts.${domain}`, ['v=STSv1; id=20240101']));
				if (url.includes(`_smtp._tls.${domain}`))
					return Promise.resolve(txt(`_smtp._tls.${domain}`, ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.endsWith('/robots.txt')) return Promise.resolve(new Response(null, { status: 404 }));
			if (url.includes('.well-known/mta-sts.txt')) return Promise.reject(new TypeError('Network connection lost'));
			return Promise.resolve(new Response(null, { status: 404 }));
		});

		const result = await run(domain, 'mta_sts');

		// Pre-fix: `passed: false` → 'not_fixed' for a control nobody measured.
		expect(result.verdict).toBe('not_assessed');
		expect(result.remainingFindings).toHaveLength(0);
		expect(result.resolvedFindings).toHaveLength(0);
		expect(result.liveRecord).toBeNull();
		expect(result.expectedMatch).toBeNull();
		expect(result.hint).toMatch(/NOT ASSESSED/);
		expect(result.hint).toMatch(/retry/i);
	});

	it('formats the not_assessed verdict in both output formats', async () => {
		const { formatValidateFix } = await import('../src/tools/validate-fix');
		const base = {
			domain: 'example.com',
			check: 'mta_sts',
			verdict: 'not_assessed' as const,
			liveRecord: null,
			expectedMatch: null,
			resolvedFindings: [],
			remainingFindings: [],
			newFindings: [],
			hint: 'NOT ASSESSED: the live re-check did not complete. Retry to re-measure.',
		};
		expect(formatValidateFix(base, 'compact')).toContain('NOT ASSESSED');
		expect(formatValidateFix(base, 'full')).toContain('Verdict: NOT ASSESSED');
	});
});
