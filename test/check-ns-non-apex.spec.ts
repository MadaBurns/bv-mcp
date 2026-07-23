// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * Install a fetch mock that answers NS only for `apex`. Every other name
 * (including the scanned non-apex label itself, and any intermediate
 * ancestors) returns NOERROR + empty answer — i.e. "exists in a parent zone,
 * not separately delegated". Modeled on `test/zone-apex.spec.ts`'s `mockNsZones`.
 */
function mockDelegatedApexOnly(apex: string, apexNs: string[]) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
		const type = typeMatch ? typeMatch[1] : '';
		if (type === 'NS' && name === apex) {
			const answers = apexNs.map((data) => ({ name: apex, type: RecordType.NS, TTL: 86400, data }));
			return Promise.resolve(createDohResponse([{ name: apex, type: RecordType.NS }], answers));
		}
		return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], []));
	});
}

describe('checkNs — non-apex', () => {
	async function run(domain: string) {
		const { checkNs } = await import('../src/tools/check-ns');
		return checkNs(domain);
	}

	it('mg.ii.inc: no CRITICAL, INFO inheritance finding, not zeroed', async () => {
		mockDelegatedApexOnly('ii.inc', ['ns1.cloudflare.com.', 'ns2.cloudflare.com.']);
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.severity === 'critical')).toBe(false);
		const info = r.findings.find((f) => f.title.match(/not a delegated zone/i));
		expect(info).toBeDefined();
		expect(info!.severity).toBe('info');
		expect(info!.detail).toContain('ii.inc');
		expect(info!.detail).toMatch(/inherited/i);
		// Inherited from a healthy 2-NS diverse-enough apex → not missing-control, not zeroed.
		expect(r.passed).toBe(true);
		expect(r.score).toBeGreaterThan(0);
	});

	it('mg.ii.inc inherits the apex NS posture score (single-NS apex → high finding)', async () => {
		mockDelegatedApexOnly('ii.inc', ['ns1.solo.com.']);
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.severity === 'critical')).toBe(false);
		expect(r.findings.some((f) => f.title.includes('Single nameserver'))).toBe(true);
	});

	it('resolver failure → inconclusive (checkStatus error), never a false CRITICAL', async () => {
		mockFetchError();
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.severity === 'critical')).toBe(false);
		expect(r.checkStatus).toBe('error');
		expect(r.partial).toBe(true);
	});
});
