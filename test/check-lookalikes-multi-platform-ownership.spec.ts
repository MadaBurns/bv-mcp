// SPDX-License-Identifier: BUSL-1.1

/**
 * #864 (regression of #263) — a same-entity domain on a DIFFERENT DNS platform
 * must not be counted as an impersonation-capable third party.
 *
 * Every fixture below is transcribed from live DoH / RDAP answers observed
 * 2026-09-04 (`dns.google/resolve`, `rdap.verisign.com`, `rdap.cctld.au`):
 *
 *   amazon.com     NS  ns-{521,264,1707,1447}.awsdns-*             (Route 53)
 *                  MX  5 amazon-smtp.amazon.com
 *   amazon.com.au  NS  ns{1,2}.amzndns.{com,co.uk,net,org}         (Amazon internal)
 *                  MX  10 amazon-smtp.amazon.com                    ← seed's own MX host
 *                  SOA dns-external-master.amazon.com. root.amazon.com. …
 *                  RDAP (auDA): NO registrant entity — registrar only
 *   amazon.com     RDAP (Verisign): thin — registrar only, no registrant
 *
 *   xero.com       NS  ns-*.awsdns-*  MX Google  SOA awsdns-hostmaster.amazon.com
 *   xero.co.nz     NS  a*.akam.net    MX Google  SOA a5-67.akam.net. hostmaster.akamai.com.
 *
 * So for the Amazon pair NEITHER the shared-NS arms NOR the #263 RDAP
 * registrant tier can fire; the only observable link is that the candidate's
 * mail AND its zone master both sit inside the seed apex. That conjunction is
 * `classifyOwnership()` step 5b — see the 2026-09-04 amendment in
 * `src/lib/ownership-attribution.ts`. For the Xero pair NO in-bailiwick record
 * exists (mail at Google, zone at Akamai), so the new arm must decline and
 * the pair keeps #263's registrant-org lane as its only link.
 *
 * Sibling specs own the other attribution lanes: `check-lookalikes.spec.ts`
 * (#263 RDAP lane, three-axis invariants), `check-lookalikes-degraded-
 * attribution.spec.ts` (#832 `unmeasured`), `ownership-attribution.spec.ts`
 * (seed-side NS arms).
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { isSharedNsHost } from '../src/tenants/discovery/shared-ns-hosts';
import type { RegistrationState } from '../src/lib/registration-state';

const { restore } = setupFetchMock();
afterEach(() => restore());

// ---------------------------------------------------------------------------
// Live-transcribed records (2026-09-04)
// ---------------------------------------------------------------------------

const AMAZON_SEED_NS = ['ns-521.awsdns-01.net', 'ns-264.awsdns-33.com', 'ns-1707.awsdns-21.co.uk', 'ns-1447.awsdns-52.org'];
const AMAZON_AU_NS = [
	'ns1.amzndns.co.uk',
	'ns2.amzndns.co.uk',
	'ns1.amzndns.org',
	'ns2.amzndns.com',
	'ns1.amzndns.com',
	'ns1.amzndns.net',
	'ns2.amzndns.org',
	'ns2.amzndns.net',
];
const AMAZON_MX_HOST = 'amazon-smtp.amazon.com';
const AMAZON_AU_SOA = { mname: 'dns-external-master.amazon.com', rname: 'root.amazon.com' };
/** What EVERY Route 53 zone's templated SOA looks like — RNAME lands inside amazon.com for unrelated tenants. */
const ROUTE53_TEMPLATED_SOA = { mname: 'ns-100.awsdns-12.com', rname: 'awsdns-hostmaster.amazon.com' };

const XERO_SEED_NS = ['ns-1911.awsdns-46.co.uk', 'ns-1391.awsdns-45.org', 'ns-983.awsdns-58.net', 'ns-90.awsdns-11.com'];
const XERO_NZ_NS = ['a13-64.akam.net', 'a1-170.akam.net', 'a28-66.akam.net', 'a5-67.akam.net', 'a10-67.akam.net', 'a14-65.akam.net'];
const GOOGLE_MX = [
	'aspmx.l.google.com',
	'alt1.aspmx.l.google.com',
	'alt2.aspmx.l.google.com',
	'aspmx2.googlemail.com',
	'aspmx3.googlemail.com',
];
const XERO_NZ_SOA = { mname: 'a5-67.akam.net', rname: 'hostmaster.akamai.com' };

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

async function loadAttribution() {
	return import('../src/lib/ownership-attribution');
}

// ---------------------------------------------------------------------------
// Unit — classifyOwnership() step 5b
// ---------------------------------------------------------------------------

describe('classifyOwnership — in-bailiwick convergence (#864, live amazon.com.au records)', () => {
	it('attributes amazon.com.au to amazon.com: MX and SOA MNAME both inside the seed apex, no shared NS', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			candidateSoa: AMAZON_AU_SOA,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('medium');
		expect(result.signals).toEqual(['mx_in_bailiwick', 'soa_in_bailiwick']);
		expect(result.rationale).toContain('amazon-smtp.amazon.com');
		expect(result.rationale).toContain('dns-external-master.amazon.com');
		// Evidence names every record the verdict rests on, so a consumer can audit it.
		expect(result.evidence).toEqual([
			{ record: 'MX', value: 'amazon-smtp.amazon.com', inSeedBailiwick: true },
			{ record: 'SOA.MNAME', value: 'dns-external-master.amazon.com', inSeedBailiwick: true },
			{ record: 'SOA.RNAME', value: 'root.amazon.com', inSeedBailiwick: true },
		]);
	});

	it('control: the same candidate WITHOUT the new inputs is still third_party (the pre-#864 verdict)', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.signals).toEqual(['distinct_infrastructure']);
	});

	it('NEGATIVE — MX alone never qualifies: a squatter copying the seed MX string stays third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		for (const soa of [undefined, null] as const) {
			const result = classifyOwnership({
				seedDomain: 'amazon.com',
				seedNs: AMAZON_SEED_NS,
				candidateDomain: 'amaz0n.com',
				registration: registered(['ns1.attacker-dns.net', 'ns2.attacker-dns.net']),
				isSharedNsHost,
				candidateMx: [AMAZON_MX_HOST],
				candidateSoa: soa,
				candidateSoaUnresolved: false,
			});
			expect(result.verdict, `candidateSoa=${String(soa)}`).toBe('third_party');
			expect(result.evidence).toBeUndefined();
		}
	});

	it('NEGATIVE — SOA RNAME is never verdict-bearing: a Route 53 squatter (templated RNAME inside amazon.com) copying the seed MX stays third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns-100.awsdns-12.com', 'ns-600.awsdns-11.net', 'ns-1200.awsdns-22.org', 'ns-1800.awsdns-33.co.uk']),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			candidateSoa: ROUTE53_TEMPLATED_SOA,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('NEGATIVE — SOA MNAME alone never qualifies: zone mastered inside the seed but mail elsewhere stays third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns1.attacker-dns.net']),
			isSharedNsHost,
			candidateMx: ['mail.attacker-dns.net'],
			candidateSoa: AMAZON_AU_SOA,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('NEGATIVE — a single MX outside the seed apex disqualifies the whole set (keeping a receive channel is the cost)', async () => {
		const { classifyOwnership, mxRoutedIntoSeed } = await loadAttribution();
		expect(mxRoutedIntoSeed([AMAZON_MX_HOST, 'mx.attacker-dns.net'], 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed([], 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed(undefined, 'amazon.com')).toBe(false);
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns1.attacker-dns.net']),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST, 'mx.attacker-dns.net'],
			candidateSoa: AMAZON_AU_SOA,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('NEGATIVE — bailiwick is label-bounded: hosts that merely END with the seed string do not count', async () => {
		const { classifyOwnership, mxRoutedIntoSeed } = await loadAttribution();
		expect(mxRoutedIntoSeed(['smtp.notamazon.com'], 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed(['amazon-smtp.amazon.com.attacker.net'], 'amazon.com')).toBe(false);
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns1.amazon.com.attacker.net']),
			isSharedNsHost,
			candidateMx: ['smtp.notamazon.com'],
			candidateSoa: { mname: 'master.notamazon.com', rname: 'root.notamazon.com' },
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('#832 law — MX routed into the seed but the SOA probe REJECTED → unmeasured, never the contrary third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			candidateSoa: null,
			candidateSoaUnresolved: true,
		});
		expect(result.verdict).toBe('unmeasured');
		expect(result.signals).toEqual(['mx_in_bailiwick']);
		expect(result.rationale).toContain('measurement gap');
		expect(result.rationale).not.toContain('no ownership signal links it');
	});

	it('a RESOLVED empty SOA (probed, nothing answered) is not a measurement gap — falls through to third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			candidateSoa: null,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('fires under a degraded SEED NS lookup too — it needs only the seed apex, like the NS in-bailiwick arm (#832 parity)', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: [],
			seedNsUnresolved: true,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			candidateSoa: AMAZON_AU_SOA,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.signals).toEqual(['mx_in_bailiwick', 'soa_in_bailiwick']);
	});

	it('seed-side arms keep precedence: a full dedicated NS match is reported as strong ns_set_match, not displaced by the medium conjunction', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.net',
			registration: registered(AMAZON_SEED_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			candidateSoa: AMAZON_AU_SOA,
			candidateSoaUnresolved: false,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.signals).toEqual(['ns_set_match']);
	});

	it('xero.co.nz (#263 shape): mail at Google and zone at Akamai — no in-bailiwick record, so the new arm declines', async () => {
		const { classifyOwnership, mxRoutedIntoSeed } = await loadAttribution();
		expect(mxRoutedIntoSeed(GOOGLE_MX, 'xero.com')).toBe(false);
		const result = classifyOwnership({
			seedDomain: 'xero.com',
			seedNs: XERO_SEED_NS,
			candidateDomain: 'xero.co.nz',
			registration: registered(XERO_NZ_NS),
			isSharedNsHost,
			candidateMx: GOOGLE_MX,
			candidateSoa: XERO_NZ_SOA,
			candidateSoaUnresolved: false,
		});
		// Structurally third_party from DNS — the pair's only link is #263's
		// registrant-org lane (wording-only), which this arm neither replaces
		// nor weakens. A verdict here would be an over-fire on shared mail.
		expect(result.verdict).toBe('third_party');
		expect(result.evidence).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// End-to-end — checkLookalikes() over the real permutation set
// ---------------------------------------------------------------------------

type RecordName = 'NS' | 'A' | 'MX' | 'SOA';
const TYPE_CODE: Record<RecordName, number> = { NS: 2, A: 1, MX: 15, SOA: 6 };
const CODE_TYPE: Record<string, RecordName> = { '2': 'NS', NS: 'NS', '1': 'A', A: 'A', '15': 'MX', MX: 'MX', '6': 'SOA', SOA: 'SOA' };

/** Per-name zone data. A record set of `'reject'` makes that lookup throw (throttled / timed out). */
type Zone = Partial<Record<RecordName, string[] | 'reject'>>;

function dohAnswer(name: string, type: RecordName, records: string[]) {
	return createDohResponse(
		[{ name, type: TYPE_CODE[type] }],
		records.map((data) => ({ name, type: TYPE_CODE[type], TTL: 300, data })),
	);
}

function soaData(soa: { mname: string; rname: string }): string {
	return `${soa.mname}. ${soa.rname}. 1 600 300 604800 900`;
}

/**
 * Install a fetch mock serving DoH from `zones`, RDAP from `rdap` (a thin
 * registrar-only document by default — what Verisign and auDA actually
 * publish), and a 200 for every HEAD probe. Returns the log of SOA query
 * names so a test can prove the #864 probe was gated, not fanned out.
 */
function installMock(zones: Record<string, Zone>, rdap: Record<string, unknown> = {}): { soaQueries: string[] } {
	const soaQueries: string[] = [];
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const parsed = new URL(url);
		const qName = parsed.searchParams.get('name');
		const qType = parsed.searchParams.get('type');
		if (qName !== null && qType !== null) {
			const name = qName.toLowerCase().replace(/\.$/, '');
			const type = CODE_TYPE[qType.toUpperCase()];
			if (type === 'SOA') soaQueries.push(name);
			const records = type ? zones[name]?.[type] : undefined;
			if (records === 'reject') return Promise.reject(new Error('DNS timeout'));
			if (records && type) return Promise.resolve(dohAnswer(name, type, records));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('rdap')) {
			const match = url.match(/\/domain\/([^/?]+)/i);
			const domain = match?.[1]?.toLowerCase() ?? '';
			const body = rdap[domain] ?? {
				objectClassName: 'domain',
				ldhName: domain,
				entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Registrar Inc']]] }],
			};
			return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/rdap+json' } }));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	});
	return { soaQueries };
}

async function runCheck(domain: string) {
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	return checkLookalikes(domain);
}

const AMAZON_SEED_ZONE: Zone = { NS: AMAZON_SEED_NS.map((h) => `${h}.`), MX: [`5 ${AMAZON_MX_HOST}.`] };

describe('checkLookalikes — amazon.com → amazon.com.au (#864 regression fixture)', () => {
	it('reports amazon.com.au as owned_by_seed with the convergence evidence, and never as an impersonation-capable lookalike', async () => {
		const { soaQueries } = installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amazon.com.au': {
				NS: AMAZON_AU_NS.map((h) => `${h}.`),
				A: ['52.95.116.115'],
				MX: [`10 ${AMAZON_MX_HOST}.`],
				SOA: [soaData(AMAZON_AU_SOA)],
			},
		});
		const result = await runCheck('amazon.com');

		const au = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'amazon.com.au');
		expect(au.length).toBeGreaterThan(0);
		const owned = au.find((f) => f.metadata?.findingAxis === 'attribution');
		expect(owned).toBeDefined();
		expect(owned!.title).toContain('likely owned by same entity');
		expect(owned!.severity).toBe('info');
		expect(owned!.metadata?.ownershipVerdict).toBe('owned_by_seed');
		expect(owned!.metadata?.ownershipStrength).toBe('medium');
		expect(owned!.metadata?.ownershipSignals).toEqual(['mx_in_bailiwick', 'soa_in_bailiwick']);
		expect(owned!.metadata?.attributionConfidence).toBe('corroborated');
		expect(owned!.metadata?.ownershipEvidence).toEqual([
			{ record: 'MX', value: 'amazon-smtp.amazon.com', inSeedBailiwick: true },
			{ record: 'SOA.MNAME', value: 'dns-external-master.amazon.com', inSeedBailiwick: true },
			{ record: 'SOA.RNAME', value: 'root.amazon.com', inSeedBailiwick: true },
		]);
		expect(owned!.detail).toContain('dns-external-master.amazon.com');

		// The customer's own domain is not an impersonation threat to itself:
		// no threat observation, no third-party verdict, not counted anywhere.
		expect(au.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(result.findings.some((f) => /mail capability detected|pre-phishing staging/i.test(f.title))).toBe(false);
		const serialised = JSON.stringify(result.findings);
		expect(serialised).not.toContain('Impersonation-shaped');
		expect(serialised).not.toContain('no ownership signal links it');
		expect(result.partial).not.toBe(true);

		// Budget: the SOA probe was issued ONLY for the candidate whose MX already
		// routed into the seed — no per-candidate fan-out across the ~84 permutations.
		expect(soaQueries).toEqual(['amazon.com.au']);
	});

	it('NEGATIVE — a Route 53 squatter (amaz0n.com) copying the seed MX string stays third_party with its threat observation intact', async () => {
		const { soaQueries } = installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amaz0n.com': {
				NS: ['ns-100.awsdns-12.com.', 'ns-600.awsdns-11.net.', 'ns-1200.awsdns-22.org.', 'ns-1800.awsdns-33.co.uk.'],
				A: ['192.0.2.10'],
				MX: [`10 ${AMAZON_MX_HOST}.`],
				// Route 53's templated SOA: MNAME is a provider host; RNAME lands inside amazon.com for EVERY tenant.
				SOA: [soaData(ROUTE53_TEMPLATED_SOA)],
			},
		});
		const result = await runCheck('amazon.com');

		const squat = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'amaz0n.com');
		expect(squat.length).toBeGreaterThan(0);
		expect(squat.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(squat.some((f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
		expect(squat.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(true);
		// The probe WAS issued (the MX half held) — and correctly declined on the SOA half.
		expect(soaQueries).toEqual(['amaz0n.com']);
	});

	it('NEGATIVE — NS hostnames that merely resemble the seed platform, plus a copied MX, do not qualify', async () => {
		installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amazom.com': {
				NS: ['ns1.amazon.com.attacker.net.', 'ns2.amzndns-hosting.net.'],
				A: ['192.0.2.11'],
				MX: [`10 ${AMAZON_MX_HOST}.`],
				SOA: ['ns1.amazon.com.attacker.net. hostmaster.attacker.net. 1 7200 900 1209600 86400'],
			},
		});
		const result = await runCheck('amazon.com');
		const squat = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'amazom.com');
		expect(squat.length).toBeGreaterThan(0);
		expect(squat.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(squat.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(true);
	});

	it('#832 law end-to-end — SOA probe rejects for amazon.com.au → unmeasured, impersonation finding withheld, result marked partial', async () => {
		installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amazon.com.au': {
				NS: AMAZON_AU_NS.map((h) => `${h}.`),
				A: ['52.95.116.115'],
				MX: [`10 ${AMAZON_MX_HOST}.`],
				SOA: 'reject',
			},
		});
		const result = await runCheck('amazon.com');

		const au = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'amazon.com.au');
		const attribution = au.filter((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution.length).toBeGreaterThan(0);
		for (const f of attribution) {
			expect(f.metadata?.ownershipVerdict).toBe('unmeasured');
			expect(f.severity).toBe('info');
		}
		expect(au.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(JSON.stringify(result.findings)).not.toContain('no ownership signal links it');
		// Transient — must not be cached for the full TTL after DNS recovers.
		expect(result.partial).toBe(true);
	});
});

describe('checkLookalikes — xero.com → xero.co.nz (#263 shape, preserved)', () => {
	it('declines the convergence arm (mail at Google, zone at Akamai) without issuing a SOA probe, and still surfaces the candidate at info', async () => {
		const { soaQueries } = installMock({
			'xero.com': { NS: XERO_SEED_NS.map((h) => `${h}.`), MX: GOOGLE_MX.map((h, i) => `${(i + 1) * 10} ${h}.`) },
			'xero.co.nz': {
				NS: XERO_NZ_NS.map((h) => `${h}.`),
				A: ['104.18.32.1'],
				MX: GOOGLE_MX.map((h, i) => `${(i + 1) * 10} ${h}.`),
				SOA: [soaData(XERO_NZ_SOA)],
			},
		});
		const result = await runCheck('xero.com');

		const nz = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'xero.co.nz');
		expect(nz.length).toBeGreaterThan(0);
		// Not an over-fire: shared-provider mail is not "routed into the seed".
		expect(
			nz.some((f) => f.metadata?.ownershipSignals !== undefined && (f.metadata.ownershipSignals as string[]).includes('mx_in_bailiwick')),
		).toBe(false);
		// Zero extra DNS: the MX precondition failed, so the SOA probe never ran.
		expect(soaQueries).toEqual([]);
		// D4 cap unchanged — reported for awareness, never suppressed, never above info on the attribution axis.
		const attribution = nz.find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		expect(attribution!.severity).toBe('info');
		expect(['third_party', 'unattributed']).toContain(attribution!.metadata?.ownershipVerdict);
	});
});
