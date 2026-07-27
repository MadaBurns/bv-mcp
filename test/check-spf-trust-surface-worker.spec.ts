import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock TXT responses for a map of name -> records.
 * Mirrors the helper in check-spf.spec.ts so this suite exercises the real DoH path.
 */
function mockMultiDomainTxt(domainRecords: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const records = domainRecords[name] ?? [];
		const answers = records.map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` }));
		return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
	});
}

/**
 * Regression coverage for issue #566: the worker-layer trust-surface post-processor
 * must recognize ESP includes the core catalog misses (Mailjet) and count every
 * delegated shared-sender include, WITHOUT changing the SPF score.
 */
describe('check_spf worker-layer trust-surface post-processor (#566)', () => {
	const SPOTTO =
		'v=spf1 include:spf.mailjet.com include:spf.protection.outlook.com include:441725607.spf01.hubspotemail.net -all';

	function baseMock(spf: string) {
		mockMultiDomainTxt({
			'spotto.ai': [spf],
			// includes resolve to simple terminal SPF records (no extra lookups / noise)
			'spf.mailjet.com': ['v=spf1 -all'],
			'spf.protection.outlook.com': ['v=spf1 -all'],
			'441725607.spf01.hubspotemail.net': ['v=spf1 -all'],
			'_spf.google.com': ['v=spf1 -all'],
			'sendgrid.net': ['v=spf1 -all'],
		});
	}

	it('recognizes all THREE delegated platforms including Mailjet (was 2)', async () => {
		baseMock(SPOTTO);
		const { checkSpf } = await import('../src/tools/check-spf');
		const result = await checkSpf('spotto.ai');

		const perInclude = result.findings.filter(
			(f) => f.metadata?.trustSurface === true && /delegates to/i.test(f.title),
		);
		const names = perInclude.map((f) => f.title);
		expect(names.some((t) => /Mailjet/i.test(t))).toBe(true);
		expect(names.some((t) => /Microsoft 365/i.test(t))).toBe(true);
		expect(names.some((t) => /HubSpot/i.test(t))).toBe(true);

		const summary = result.findings.find((f) => f.metadata?.platformCount != null);
		expect(summary).toBeDefined();
		expect(summary!.metadata?.platformCount).toBe(3);
		expect(summary!.title).toContain('3 shared platforms');
	});

	it('still reports exactly 2 for a two-recognized-include record', async () => {
		const spf = 'v=spf1 include:spf.protection.outlook.com include:441725607.spf01.hubspotemail.net -all';
		baseMock(spf);
		const { checkSpf } = await import('../src/tools/check-spf');
		const result = await checkSpf('spotto.ai');

		const summary = result.findings.find((f) => f.metadata?.platformCount != null);
		expect(summary).toBeDefined();
		expect(summary!.metadata?.platformCount).toBe(2);
		expect(summary!.title).toContain('2 shared platforms');
	});

	it('counts an unrecognized broad shared sender toward the trust surface total', async () => {
		// _spf.google.com is recognized; spf.unknownesp.io is an unrecognized broad ESP-style host.
		const spf = 'v=spf1 include:_spf.google.com include:spf.unknownesp.io -all';
		mockMultiDomainTxt({
			'spotto.ai': [spf],
			'_spf.google.com': ['v=spf1 -all'],
			'spf.unknownesp.io': ['v=spf1 -all'],
		});
		const { checkSpf } = await import('../src/tools/check-spf');
		const result = await checkSpf('spotto.ai');

		const summary = result.findings.find((f) => f.metadata?.platformCount != null);
		expect(summary).toBeDefined();
		expect(summary!.metadata?.platformCount).toBe(2);
	});

	it('leaves the SPF score byte-identical to the core checkSPF result', async () => {
		baseMock(SPOTTO);
		const { checkSPF } = await import('@blackveil/dns-checks');
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');
		const core = await checkSPF('spotto.ai', makeQueryDNS());

		baseMock(SPOTTO);
		const { checkSpf } = await import('../src/tools/check-spf');
		const worker = await checkSpf('spotto.ai');

		expect(worker.score).toBe(core.score);
		expect(worker.passed).toBe(core.passed);
		expect(worker.checkStatus).toBe(core.checkStatus);
	});
});
