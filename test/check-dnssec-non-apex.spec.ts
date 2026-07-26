// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * Install a fetch mock that answers NS only for `ii.inc` (so `resolveZoneApex`
 * classifies `mg.ii.inc` as `inherited`, apex `ii.inc`) and answers a fully
 * SIGNED DNSSEC posture (AD=true, DNSKEY+DS present) at `ii.inc` only.
 * `mg.ii.inc` has no DNSKEY/DS of its own — every other name/type returns
 * NOERROR + empty answer, and the `A`-record AD-probe reflects the apex's
 * signed status. Modeled on `test/check-ns-non-apex.spec.ts` /
 * `test/check-caa-non-apex.spec.ts`.
 */
function mockSignedApexOnly(apex: string) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
		const type = typeMatch ? typeMatch[1] : '';

		if (type === 'NS' && name === apex) {
			const answers = [
				{ name: apex, type: RecordType.NS, TTL: 86400, data: 'ns1.cloudflare.com.' },
				{ name: apex, type: RecordType.NS, TTL: 86400, data: 'ns2.cloudflare.com.' },
			];
			return Promise.resolve(createDohResponse([{ name: apex, type: RecordType.NS }], answers));
		}

		if (type === 'A' && name === apex) {
			return Promise.resolve(
				createDohResponse([{ name: apex, type: 1 }], [{ name: apex, type: RecordType.A, TTL: 300, data: '93.184.216.34' }], {
					ad: true,
				}),
			);
		}
		if (type === 'A') {
			// Non-apex A probe: unsigned in isolation (the false-positive this fix targets).
			return Promise.resolve(
				createDohResponse([{ name, type: 1 }], [{ name, type: RecordType.A, TTL: 300, data: '93.184.216.34' }], { ad: false }),
			);
		}

		if (type === 'DNSKEY' && name === apex) {
			return Promise.resolve(
				createDohResponse(
					[{ name: apex, type: RecordType.DNSKEY }],
					[{ name: apex, type: RecordType.DNSKEY, TTL: 300, data: '257 3 13 mdsswUyr3DPW...' }],
				),
			);
		}
		if (type === 'DS' && name === apex) {
			return Promise.resolve(
				createDohResponse(
					[{ name: apex, type: RecordType.DS }],
					[{ name: apex, type: RecordType.DS, TTL: 300, data: '12345 13 2 abc123...' }],
				),
			);
		}

		// Everything else (NS/DNSKEY/DS/NSEC3PARAM on mg.ii.inc, NSEC3PARAM on ii.inc, etc.) — empty NOERROR.
		return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], []));
	});
}

describe('checkDnssec — non-apex evaluate-at-signed-apex', () => {
	async function run(domain: string) {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('mg.ii.inc inherits DNSSEC posture from signed apex ii.inc — no "DNSSEC not enabled"', async () => {
		mockSignedApexOnly('ii.inc');
		const r = await run('mg.ii.inc');
		expect(r.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(false);
	});

	it('mg.ii.inc carries an INFO finding referencing the signed apex ii.inc', async () => {
		mockSignedApexOnly('ii.inc');
		const r = await run('mg.ii.inc');
		const inherited = r.findings.find((f) => f.severity === 'info' && /ii\.inc/.test(f.detail ?? '') && /inherited/i.test(f.detail ?? ''));
		expect(inherited).toBeDefined();
	});

	it('ii.inc (apex) still evaluates on its own posture — signed, no penalty', async () => {
		mockSignedApexOnly('ii.inc');
		const r = await run('ii.inc');
		expect(r.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(false);
	});
});

/**
 * NS present at `apex` (so `mg.ii.inc` classifies `inherited`), but the apex is
 * NOT DNSSEC-signed: AD=false everywhere, no DNSKEY/DS anywhere.
 */
function mockUnsignedApexOnly(apex: string) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
		const type = typeMatch ? typeMatch[1] : '';

		if (type === 'NS' && name === apex) {
			const answers = [
				{ name: apex, type: RecordType.NS, TTL: 86400, data: 'ns1.cloudflare.com.' },
				{ name: apex, type: RecordType.NS, TTL: 86400, data: 'ns2.cloudflare.com.' },
			];
			return Promise.resolve(createDohResponse([{ name: apex, type: RecordType.NS }], answers));
		}
		if (type === 'A') {
			// Resolves, but UNSIGNED (AD=false) — including at the apex.
			return Promise.resolve(
				createDohResponse([{ name, type: 1 }], [{ name, type: RecordType.A, TTL: 300, data: '93.184.216.34' }], { ad: false }),
			);
		}
		// No DNSKEY/DS/NSEC3PARAM anywhere → genuinely unsigned.
		return Promise.resolve(createDohResponse([{ name, type: RecordType.NS }], []));
	});
}

describe('checkDnssec — inherited from an UNSIGNED apex (wording must not contradict the verdict)', () => {
	async function run(domain: string) {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('mg.ii.inc: apex genuinely unsigned → real "not enabled" fires AND the inheritance note never claims the zone is "signed"', async () => {
		mockUnsignedApexOnly('ii.inc');
		const r = await run('mg.ii.inc');

		// The apex is genuinely unsigned → the real verdict must still surface.
		expect(r.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(true);

		// The inheritance note must attribute posture to the apex WITHOUT asserting it is
		// "signed" (that would contradict the "not enabled" verdict in the same result).
		const inherited = r.findings.find((f) => f.severity === 'info' && /inherited/i.test(f.detail ?? ''));
		expect(inherited).toBeDefined();
		expect(inherited!.title.toLowerCase()).not.toContain('signed');
		expect((inherited!.detail ?? '').toLowerCase()).not.toContain('signed');
	});
});
