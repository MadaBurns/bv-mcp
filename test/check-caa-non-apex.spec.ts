// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * Install a fetch mock that answers NS only for `ii.inc` (so `resolveZoneApex`
 * classifies `mg.ii.inc` as `inherited`, apex `ii.inc`) and answers CAA only for
 * the names present in `caaZones`. Every other name/type returns NOERROR + empty
 * answer. Modeled on `test/zone-apex.spec.ts`'s `mockNsZones` and
 * `test/check-ns-non-apex.spec.ts`'s `mockDelegatedApexOnly`.
 */
function mockCaaZones(caaZones: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
		const type = typeMatch ? typeMatch[1] : '';

		if (type === 'NS' && name === 'ii.inc') {
			const answers = [
				{ name, type: RecordType.NS, TTL: 86400, data: 'ns1.cloudflare.com.' },
				{ name, type: RecordType.NS, TTL: 86400, data: 'ns2.cloudflare.com.' },
			];
			return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], answers));
		}
		if (type === 'CAA' && caaZones[name]?.length) {
			const answers = caaZones[name].map((data) => ({ name, type: RecordType.CAA, TTL: 300, data }));
			return Promise.resolve(createDohResponse([{ name, type: RecordType.CAA }], answers));
		}
		return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], []));
	});
}

describe('checkCaa — non-apex RFC 8659 climb', () => {
	async function run(domain: string) {
		const { checkCaa } = await import('../src/tools/check-caa');
		return checkCaa(domain);
	}

	it('mg.ii.inc inherits CAA from ii.inc (no "No CAA records")', async () => {
		mockCaaZones({ 'ii.inc': ['0 issue "letsencrypt.org"'] });
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.title === 'No CAA records')).toBe(false);
		const inherited = r.findings.find((f) => f.detail?.match(/inherited from ii\.inc/i));
		expect(inherited).toBeDefined();
		expect(inherited!.severity).toBe('info');
		expect(r.passed).toBe(true);
	});

	it('mg.ii.inc with no CAA anywhere up to floor still reports No CAA records', async () => {
		mockCaaZones({});
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.title === 'No CAA records')).toBe(true);
		expect(r.findings.some((f) => /inherited/i.test(f.detail))).toBe(false);
	});

	it('ii.inc (apex) with no CAA still reports the plain "No CAA records" finding (unchanged)', async () => {
		mockCaaZones({});
		const r = await run('ii.inc');
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].title).toBe('No CAA records');
		expect(r.findings[0].severity).toBe('medium');
	});
});
