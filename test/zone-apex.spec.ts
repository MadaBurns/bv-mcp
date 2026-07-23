// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * Install a fetch mock that returns NS answers only for the domains in `nsZones`.
 * Every other name returns NOERROR + empty answer (Status 0, no Answer) — i.e. a
 * name that exists in a parent zone but is not itself delegated.
 */
function mockNsZones(nsZones: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
		const type = typeMatch ? typeMatch[1] : '';
		if (type === 'NS' && nsZones[name]?.length) {
			const answers = nsZones[name].map((data) => ({ name, type: RecordType.NS, TTL: 86400, data }));
			return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], answers));
		}
		return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], []));
	});
}

describe('resolveZoneApex', () => {
	async function run(domain: string) {
		const { resolveZoneApex } = await import('../src/lib/zone-apex');
		return resolveZoneApex(domain);
	}

	it('treats a registrable apex as apex without walking', async () => {
		mockNsZones({ 'ii.inc': ['ns1.cloudflare.com.', 'ns2.cloudflare.com.'] });
		const z = await run('ii.inc');
		expect(z.isApex).toBe(true);
		expect(z.delegationStatus).toBe('apex');
		expect(z.zoneApex).toBe('ii.inc');
	});

	it('resolves a non-delegated single-label subdomain to its apex', async () => {
		mockNsZones({ 'ii.inc': ['ns1.cloudflare.com.', 'ns2.cloudflare.com.'] });
		const z = await run('mg.ii.inc');
		expect(z.isApex).toBe(false);
		expect(z.delegationStatus).toBe('inherited');
		expect(z.zoneApex).toBe('ii.inc');
		expect(z.apexNsRecords).toEqual(['ns1.cloudflare.com', 'ns2.cloudflare.com']);
	});

	it('walks multi-label depth to the correct apex', async () => {
		mockNsZones({ 'example.com': ['ns1.p.net.', 'ns2.p.net.'] });
		const z = await run('a.b.c.example.com');
		expect(z.zoneApex).toBe('example.com');
		expect(z.delegationStatus).toBe('inherited');
	});

	it('treats a delegated subdomain (own NS) as its own apex', async () => {
		mockNsZones({ 'sub.example.com': ['ns1.child.net.', 'ns2.child.net.'], 'example.com': ['ns1.p.net.'] });
		const z = await run('sub.example.com');
		expect(z.isApex).toBe(true);
		expect(z.delegationStatus).toBe('apex');
		expect(z.zoneApex).toBe('sub.example.com');
		expect(z.apexNsRecords).toEqual(['ns1.child.net', 'ns2.child.net']);
	});

	it('does not walk past a multi-part public suffix (foo.co.uk)', async () => {
		mockNsZones({ 'foo.co.uk': ['ns1.p.net.'] });
		const z = await run('foo.co.uk');
		expect(z.isApex).toBe(true);
		expect(z.registrableDomain).toBe('foo.co.uk');
	});

	it('does not walk past a private suffix (foo.github.io)', async () => {
		mockNsZones({});
		const z = await run('foo.github.io');
		expect(z.isApex).toBe(true);
		expect(z.registrableDomain).toBe('foo.github.io');
	});

	it('classifies an apex with no NS anywhere as undelegated_broken', async () => {
		mockNsZones({}); // no zone answers NS
		const z = await run('mg.ii.inc');
		expect(z.delegationStatus).toBe('undelegated_broken');
		expect(z.apexNsRecords).toEqual([]);
	});

	it('returns unknown on resolver failure', async () => {
		mockFetchError();
		const z = await run('mg.ii.inc');
		expect(z.delegationStatus).toBe('unknown');
		expect(z.isApex).toBe(false);
	});
});
