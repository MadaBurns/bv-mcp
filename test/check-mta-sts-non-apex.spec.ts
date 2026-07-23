// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * Install a single fetch mock that answers:
 * - NS for `apex` only (every other NS query, including the scanned non-apex
 *   label and any intermediate ancestors, returns NOERROR + empty — "exists in
 *   a parent zone, not separately delegated"). Modeled on
 *   `test/check-ns-non-apex.spec.ts`'s `mockDelegatedApexOnly`.
 * - MX/TXT records for `domain` per the supplied maps (default: none present).
 *
 * All other DoH lookups (including MX, since the non-apex short-circuit never
 * probes it) fall back to an empty NOERROR answer.
 */
function mockNonApexMailQueries(opts: {
	domain: string;
	apex: string;
	apexNs: string[];
	mxRecords?: Array<{ priority: number; exchange: string }>;
}) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/[?&]name=([^&]+)/);
		const typeMatch = url.match(/[?&]type=([^&]+)/);
		const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
		const type = typeMatch ? typeMatch[1] : '';

		if (type === 'NS' && name === opts.apex) {
			const answers = opts.apexNs.map((data) => ({ name: opts.apex, type: RecordType.NS, TTL: 86400, data }));
			return Promise.resolve(createDohResponse([{ name: opts.apex, type: RecordType.NS }], answers));
		}
		if (type === 'MX' && name === opts.domain && opts.mxRecords) {
			const answers = opts.mxRecords.map((r) => ({
				name: opts.domain,
				type: RecordType.MX,
				TTL: 300,
				data: `${r.priority} ${r.exchange}.`,
			}));
			return Promise.resolve(createDohResponse([{ name: opts.domain, type: RecordType.MX }], answers));
		}
		// Covers NS on the scanned label/ancestors, _mta-sts/_smtp._tls TXT, and
		// any unmapped MX lookup — all NOERROR + empty.
		return Promise.resolve(createDohResponse([{ name, type: (RecordType as unknown as Record<string, number>)[type] ?? 0 }], []));
	});
}

describe('checkMtaSts — non-apex', () => {
	async function run(domain: string) {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	it('mg.ii.inc: no MTA-STS/TLS-RPT/MX → info "not applicable", never missingControl', async () => {
		mockNonApexMailQueries({ domain: 'mg.ii.inc', apex: 'ii.inc', apexNs: ['ns1.cloudflare.com.', 'ns2.cloudflare.com.'] });

		const r = await run('mg.ii.inc');

		expect(r.category).toBe('mta_sts');
		expect(r.findings).toHaveLength(1);
		const [finding] = r.findings;
		expect(finding.title).toMatch(/not applicable/i);
		expect(finding.severity).toBe('info');
		expect(finding.detail).toMatch(/per mail host/i);
		expect(finding.detail).toMatch(/not inherited/i);
		expect(finding.metadata?.missingControl).not.toBe(true);

		expect(r.findings.some((f) => f.severity === 'medium' || f.severity === 'high' || f.severity === 'critical')).toBe(false);
		expect(r.passed).toBeTruthy();
	});
});

describe('checkMtaSts — apex regression (unchanged)', () => {
	async function run(domain: string) {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	it('example.com with MX + no MTA-STS/TLS-RPT still yields medium + missingControl', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string) => {
			const nameMatch = url.match(/[?&]name=([^&]+)/);
			const typeMatch = url.match(/[?&]type=([^&]+)/);
			const name = nameMatch ? decodeURIComponent(nameMatch[1]).replace(/\.$/, '') : '';
			const type = typeMatch ? typeMatch[1] : '';

			if (type === 'MX' && name === 'example.com') {
				const answers = [{ name: 'example.com', type: RecordType.MX, TTL: 300, data: '10 mx1.example.com.' }];
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: RecordType.MX }], answers));
			}
			// NS at the registrable apex itself → isApex short-circuits query-free in
			// resolveZoneApex, so this branch only covers the TXT lookups (none present).
			return Promise.resolve(createDohResponse([{ name, type: (RecordType as unknown as Record<string, number>)[type] ?? 0 }], []));
		});

		const r = await run('example.com');

		const missing = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(missing).toBeDefined();
		expect(missing!.severity).toBe('medium');
		expect(missing!.metadata?.missingControl).toBe(true);
	});
});
