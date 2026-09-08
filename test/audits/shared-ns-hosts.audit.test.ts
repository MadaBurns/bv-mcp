// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: SHARED_NS_APEXES coverage for the NS-correlator multi-tenant filter.
 *
 * The well-known parking services and registrar-default NS hosts MUST be
 * classified as shared-tenant so an overlap on their hostnames doesn't
 * inflate brand-discovery confidence. Conversely, hyperscale managed DNS
 * (Cloudflare, Route 53, GCP) MUST NOT be classified as shared-tenant —
 * those providers assign unique NS hostnames per account, so an overlap
 * there is genuine ownership evidence.
 *
 * Ref: v2.14.0 audit, LR-2 (Slice 6 defense-in-depth).
 */

import { describe, it, expect } from 'vitest';
import {
	isPooledSharedNsHost,
	isSharedNsHost,
	POOLED_SHARED_NS_APEXES,
	SHARED_NS_APEXES,
} from '../../src/tenants/discovery/shared-ns-hosts';

const SHARED_NS_MUST_MATCH: ReadonlyArray<readonly [string, string]> = [
	// Parking services
	['ns1.sedoparking.com', 'Sedo parking'],
	['ns2.sedoparking.com', 'Sedo parking'],
	['ns1.parkingcrew.com', 'ParkingCrew'],
	['dns1.bodis.com', 'Bodis parking'],
	['ns1.dan.com', 'Dan.com / Sedo parking'],
	['ns1.above.com', 'Above.com parking'],
	['ns1.dnsowl.com', 'DNSOwl parking'],
	// GoDaddy default / parked
	['ns01.domaincontrol.com', 'GoDaddy default NS (parked or default-registered)'],
	['ns73.domaincontrol.com', 'GoDaddy default NS — high-number variant'],
	['ns1.secureserver.net', 'GoDaddy secureserver'],
	// Namecheap registrar default
	['dns1.registrar-servers.com', 'Namecheap registrar-default NS'],
	// one.com shared hosting — identical pair for every tenant (#929, live 2026-09-09)
	['ns01.one.com', 'one.com shared hosting — every tenant gets ns01/ns02'],
	['ns02.one.com', 'one.com shared hosting — every tenant gets ns01/ns02'],
	// Akamai — hostnames are shared across unrelated customers (2026-07-26
	// correctness-defects design §3.3: bnz.co.nz shares a9-65.akam.net with
	// anz.co.nz and a3-67.akam.net with westpac.co.nz — three competing banks).
	['a1-97.akam.net', 'Akamai — shared across unrelated customer zones'],
	['a9-65.akam.net', 'Akamai — shared across unrelated customer zones'],
];

const SHARED_NS_MUST_NOT_MATCH: ReadonlyArray<readonly [string, string]> = [
	// Hyperscale managed DNS — unique NS per account, overlap IS evidence
	['alice.ns.cloudflare.com', 'Cloudflare assigns unique NS per account'],
	['bob.ns.cloudflare.com', 'Cloudflare assigns unique NS per account'],
	['ns-1234.awsdns-56.com', 'AWS Route 53 assigns unique NS per hosted zone'],
	['ns-cloud-a1.googledomains.com', 'GCP Cloud DNS unique-per-zone'],
	// User-controlled / clearly unrelated
	['ns1.example.com', 'Generic example domain'],
	['blackveilsecurity.com', 'Our own apex (defensive)'],
];

describe('SHARED_NS_APEXES coverage — parking / registrar-default NS', () => {
	for (const [ns, reason] of SHARED_NS_MUST_MATCH) {
		it(`classifies ${ns} as shared-tenant (${reason})`, () => {
			expect(isSharedNsHost(ns)).toBe(true);
		});
	}
});

describe('SHARED_NS_APEXES non-coverage — hyperscale DNS must remain ownership-bearing', () => {
	for (const [ns, reason] of SHARED_NS_MUST_NOT_MATCH) {
		it(`does NOT classify ${ns} as shared-tenant (${reason})`, () => {
			expect(isSharedNsHost(ns)).toBe(false);
		});
	}

	it('returns false for empty / whitespace input (defensive)', () => {
		expect(isSharedNsHost('')).toBe(false);
		expect(isSharedNsHost('   ')).toBe(false);
	});
});

describe('POOLED_SHARED_NS_APEXES — the only shared providers a complete NS-set match may credit (#929)', () => {
	it('is a strict subset of SHARED_NS_APEXES (a pooled host must also be excluded from the dedicated arm)', () => {
		expect(POOLED_SHARED_NS_APEXES.size).toBeGreaterThan(0);
		expect(POOLED_SHARED_NS_APEXES.size).toBeLessThan(SHARED_NS_APEXES.size);
		for (const apex of POOLED_SHARED_NS_APEXES) expect(SHARED_NS_APEXES.has(apex)).toBe(true);
	});

	it('classes Akamai as pooled (six hosts per zone from a large pool — a 6/6 match is one account)', () => {
		expect(isPooledSharedNsHost('a1-97.akam.net')).toBe(true);
	});

	for (const [ns] of SHARED_NS_MUST_MATCH) {
		if (ns.endsWith('.akam.net')) continue;
		it(`does NOT class ${ns} as pooled — every tenant of that platform receives the same set`, () => {
			expect(isPooledSharedNsHost(ns)).toBe(false);
		});
	}
});
