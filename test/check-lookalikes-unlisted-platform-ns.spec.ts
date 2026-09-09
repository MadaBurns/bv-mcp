// SPDX-License-Identifier: BUSL-1.1

/**
 * #939 — the class behind #929, beyond one.com: every uniform-set or
 * small-pool nameserver platform that was NOT in `SHARED_NS_APEXES` still
 * reached `classifyOwnership()` step 3 ("dedicated" `ns_set_match`) and
 * yielded `owned_by_seed` / `strong` on a complete match, exactly as one.com
 * did before PR #937.
 *
 * Fixtures are transcribed from live records (Cloudflare + Google DoH,
 * 2026-09-09; both vantages agreed on every row — the full table is in the
 * #939 PR). Each pair below is two visibly unrelated organisations that
 * received the IDENTICAL complete NS set from the platform:
 *
 *   Hostinger      debugpoint.com / sweetberry.gr        ns1, ns2.dns-parking.com
 *   IONOS          calcionapoli24.it / aicateringequipments.ie
 *                                                        ns1045.ui-dns.{biz,com,de,org}
 *   Cloud DNS      americanbanker.com / edmontonjournal.com
 *                                                        ns-cloud-b1..b4.googledomains.com
 *   Squarespace    usahockeymagazine.com (p05) / biosites.com (p06)
 *                                                        ns01-04.squarespacedns.com + dns1-4.p0N.nsone.net
 *   Porkbun        enby.software / spqrome.org           curitiba, fortaleza, maceio, salvador.ns.porkbun.com
 *   digital.govt.nz  13 NZ agencies                      ns1..ns5.digital.govt.nz
 *   Enterprise-gated corporate registrar  natwest.com / natwest.co.uk  udns1.cscdns.net, udns2.cscdns.uk
 *   Yandex Cloud (PSL private suffix)  bigenc.ru / 4lapy.ru  ns1, ns2.yandexcloud.net
 *
 * The corporate-registrar pair is deliberately a seed and its OWN defensive
 * registration: the enterprise-gated platforms (that registrar, MarkMonitor, digital.govt.nz,
 * UltraDNS) are not self-service, so listing them is a disclosed
 * behaviour change on enterprise-tier output — the customer's own
 * same-platform name drops from `owned_by_seed` to `unattributed`, gains the
 * uncapped threat observation in check_lookalikes and loses the owned-only
 * "lacks DMARC" rung in check_shadow_domains. The cases below PIN that
 * decision (#947 review; the own-name wording is issue #949).
 *
 * Every case asserts the verdict is `unattributed` or `third_party` and NEVER
 * `owned_by_seed`. The list is the only thing that changed — the mechanism
 * (#937) is untouched — so each case is red with the entry removed from
 * `SHARED_NS_APEXES` and green with it present (verified before commit).
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { isSharedNsHost, isPooledSharedNsHost } from '../src/tenants/discovery/shared-ns-hosts';
import type { RegistrationState } from '../src/lib/registration-state';
import type { DohResponse } from '../src/lib/dns-types';

const { restore } = setupFetchMock();
afterEach(() => restore());

// ---------------------------------------------------------------------------
// Live-transcribed NS sets (2026-09-09)
// ---------------------------------------------------------------------------

const HOSTINGER_NS = ['ns1.dns-parking.com', 'ns2.dns-parking.com'];
const IONOS_NS = ['ns1045.ui-dns.biz', 'ns1045.ui-dns.com', 'ns1045.ui-dns.de', 'ns1045.ui-dns.org'];
const CLOUD_DNS_B = [
	'ns-cloud-b1.googledomains.com',
	'ns-cloud-b2.googledomains.com',
	'ns-cloud-b3.googledomains.com',
	'ns-cloud-b4.googledomains.com',
];
const SQUARESPACE_NS = ['ns01.squarespacedns.com', 'ns02.squarespacedns.com', 'ns03.squarespacedns.com', 'ns04.squarespacedns.com'];
const nsonePool = (n: string) => [`dns1.${n}.nsone.net`, `dns2.${n}.nsone.net`, `dns3.${n}.nsone.net`, `dns4.${n}.nsone.net`];
const PORKBUN_NS = ['curitiba.ns.porkbun.com', 'fortaleza.ns.porkbun.com', 'maceio.ns.porkbun.com', 'salvador.ns.porkbun.com'];
const CORP_REGISTRAR_UDNS = ['udns1.cscdns.net', 'udns2.cscdns.uk'];
const YANDEX_CLOUD_NS = ['ns1.yandexcloud.net', 'ns2.yandexcloud.net'];
const DIGITAL_GOVT_NZ_NS = [
	'ns1.digital.govt.nz',
	'ns2.digital.govt.nz',
	'ns3.digital.govt.nz',
	'ns4.digital.govt.nz',
	'ns5.digital.govt.nz',
];
/** Every agency observed on the platform, 2026-09-09 (seed `nzta.govt.nz` excluded). */
const DIGITAL_GOVT_NZ_TENANTS = [
	'dia.govt.nz',
	'customs.govt.nz',
	'linz.govt.nz',
	'stats.govt.nz',
	'treasury.govt.nz',
	'tec.govt.nz',
	'corrections.govt.nz',
	'mfat.govt.nz',
	'beehive.govt.nz',
	'dpmc.govt.nz',
	'nzdf.mil.nz',
	'tpk.govt.nz',
];

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

async function loadAttribution() {
	return import('../src/lib/ownership-attribution');
}

type Case = { platform: string; seed: string; candidate: string; seedNs: string[]; candidateNs: string[] };

const IDENTICAL_SET_CASES: Case[] = [
	{ platform: 'Hostinger', seed: 'debugpoint.com', candidate: 'sweetberry.gr', seedNs: HOSTINGER_NS, candidateNs: HOSTINGER_NS },
	{ platform: 'IONOS', seed: 'calcionapoli24.it', candidate: 'aicateringequipments.ie', seedNs: IONOS_NS, candidateNs: IONOS_NS },
	{
		platform: 'Google Cloud DNS',
		seed: 'americanbanker.com',
		candidate: 'edmontonjournal.com',
		seedNs: CLOUD_DNS_B,
		candidateNs: CLOUD_DNS_B,
	},
	{ platform: 'Porkbun', seed: 'enby.software', candidate: 'spqrome.org', seedNs: PORKBUN_NS, candidateNs: PORKBUN_NS },
	{
		platform: 'Enterprise-gated corporate registrar (own defensive registration)',
		seed: 'natwest.com',
		candidate: 'natwest.co.uk',
		seedNs: CORP_REGISTRAR_UDNS,
		candidateNs: CORP_REGISTRAR_UDNS,
	},
	{
		platform: 'Yandex Cloud (PSL private suffix — hostname-keyed entries)',
		seed: 'bigenc.ru',
		candidate: '4lapy.ru',
		seedNs: YANDEX_CLOUD_NS,
		candidateNs: YANDEX_CLOUD_NS,
	},
	{
		platform: 'digital.govt.nz',
		seed: 'nzta.govt.nz',
		candidate: 'dia.govt.nz',
		seedNs: DIGITAL_GOVT_NZ_NS,
		candidateNs: DIGITAL_GOVT_NZ_NS,
	},
	{
		platform: 'Squarespace (same NS1 pool member)',
		seed: 'usahockeymagazine.com',
		candidate: 'biosites.com',
		seedNs: [...SQUARESPACE_NS, ...nsonePool('p05')],
		candidateNs: [...SQUARESPACE_NS, ...nsonePool('p05')],
	},
];

// ---------------------------------------------------------------------------
// Provider classification
// ---------------------------------------------------------------------------

describe('shared-ns-hosts — the #939 platforms are shared, and none is pooled', () => {
	for (const c of IDENTICAL_SET_CASES) {
		it(`${c.platform}: every host of the set is a shared-tenant host and none earns the pooled complete-match arm`, () => {
			for (const host of c.seedNs) {
				expect(isSharedNsHost(host)).toBe(true);
				expect(isPooledSharedNsHost(host)).toBe(false);
			}
		});
	}
});

// ---------------------------------------------------------------------------
// Unit — classifyOwnership()
// ---------------------------------------------------------------------------

describe('classifyOwnership — an identical platform set is never owned_by_seed (#939)', () => {
	for (const c of IDENTICAL_SET_CASES) {
		it(`${c.platform}: ${c.candidate} on the same set as ${c.seed} is unattributed on ns_shared_platform, never owned_by_seed / strong`, async () => {
			const { classifyOwnership } = await loadAttribution();
			const result = classifyOwnership({
				seedDomain: c.seed,
				seedNs: c.seedNs,
				candidateDomain: c.candidate,
				registration: registered(c.candidateNs.slice()),
				isSharedNsHost,
				isPooledSharedNsHost,
			});
			expect(result.verdict).toBe('unattributed');
			expect(result.strength).toBe('none');
			expect(result.signals).toEqual(['ns_shared_platform']);
			expect(result.rationale).not.toContain('dedicated');
			expect(result.rationale).not.toContain('none on a known shared-tenant provider');
		});
	}

	it('Squarespace: the four squarespacedns hosts alone (4/8 = the ns_set_match bar) do not attribute a tenant on a different NS1 pool member', async () => {
		// Before #939 `squarespacedns.com` was unlisted, so the four platform
		// hosts counted as "dedicated": 4/8 >= 50% and >= 2 → owned_by_seed,
		// strong, on a set every Squarespace tenant carries.
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'usahockeymagazine.com',
			seedNs: [...SQUARESPACE_NS, ...nsonePool('p05')],
			candidateDomain: 'biosites.com',
			registration: registered([...SQUARESPACE_NS, ...nsonePool('p06')]),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).not.toBe('owned_by_seed');
		expect(result.strength).toBe('none');
		expect(result.signals).toEqual(['ns_shared_platform']);
		// The candidate's p06 quartet is genuinely distinct from the seed's p05.
		expect(result.verdict).toBe('third_party');
		expect(result.rationale).toContain('remaining nameservers are distinct');
	});

	it("the squatter's cheapest shape on Hostinger — the seed's pair PLUS its own host — is third_party, never owned", async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'debugpoint.com',
			seedNs: HOSTINGER_NS,
			candidateDomain: 'debugpoin.com',
			registration: registered([...HOSTINGER_NS, 'ns1.attacker.example']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.signals).toEqual(['ns_shared_platform']);
	});

	it('a genuinely dedicated pair still attributes — the list did not widen into the dedicated arm', async () => {
		const { classifyOwnership } = await loadAttribution();
		const dedicated = ['ns1.corp-dns.example', 'ns2.corp-dns.example'];
		const result = classifyOwnership({
			seedDomain: 'corp.example',
			seedNs: dedicated,
			candidateDomain: 'corp-sibling.example',
			registration: registered(dedicated.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.signals).toEqual(['ns_set_match']);
	});
});

// ---------------------------------------------------------------------------
// discover_brand_domains — the NS correlator on the real digital.govt.nz data
// ---------------------------------------------------------------------------

function nsResponse(name: string, hosts: string[]): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name, type: 2 }],
		Answer: hosts.map((data) => ({ name, type: 2, TTL: 3600, data: `${data}.` })),
	};
}

describe('correlateNs — a shared national platform does not co-own unrelated agencies (#939)', () => {
	it('nzta.govt.nz on digital.govt.nz reports NO co-owned domain among the 12 other agencies on the identical set', async () => {
		const { correlateNs } = await import('../src/tenants/discovery/ns-correlator');
		const zones: Record<string, string[]> = { 'nzta.govt.nz': DIGITAL_GOVT_NZ_NS };
		for (const agency of DIGITAL_GOVT_NZ_TENANTS) zones[agency] = DIGITAL_GOVT_NZ_NS;
		const dnsQuery = vi.fn(async (name: string) => {
			const key = name.toLowerCase().replace(/\.$/, '');
			const hosts = zones[key];
			return hosts ? nsResponse(key, hosts) : { ...nsResponse(key, []), Answer: [] };
		});
		const result = await correlateNs('nzta.govt.nz', { dnsQuery, candidateDomains: DIGITAL_GOVT_NZ_TENANTS });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('Cloud DNS set b: americanbanker.com does not co-own edmontonjournal.com', async () => {
		const { correlateNs } = await import('../src/tenants/discovery/ns-correlator');
		const zones: Record<string, string[]> = { 'americanbanker.com': CLOUD_DNS_B, 'edmontonjournal.com': CLOUD_DNS_B };
		const dnsQuery = vi.fn(async (name: string) => {
			const key = name.toLowerCase().replace(/\.$/, '');
			const hosts = zones[key];
			return hosts ? nsResponse(key, hosts) : { ...nsResponse(key, []), Answer: [] };
		});
		const result = await correlateNs('americanbanker.com', { dnsQuery, candidateDomains: ['edmontonjournal.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// End-to-end — checkLookalikes() and checkShadowDomains() on the Hostinger pair
// ---------------------------------------------------------------------------

type RecordName = 'NS' | 'A' | 'MX' | 'SOA' | 'TXT';
const TYPE_CODE: Record<RecordName, number> = { NS: 2, A: 1, MX: 15, SOA: 6, TXT: 16 };
const CODE_TYPE: Record<string, RecordName> = {
	'2': 'NS',
	NS: 'NS',
	'1': 'A',
	A: 'A',
	'15': 'MX',
	MX: 'MX',
	'6': 'SOA',
	SOA: 'SOA',
	'16': 'TXT',
	TXT: 'TXT',
};
type Zone = Partial<Record<RecordName, string[]>>;

function dohAnswer(name: string, type: RecordName, records: string[]) {
	return createDohResponse(
		[{ name, type: TYPE_CODE[type] }],
		records.map((data) => ({ name, type: TYPE_CODE[type], TTL: 300, data: type === 'TXT' ? `"${data}"` : data })),
	);
}

/** DoH from `zones`; a registrar-only RDAP document; 200 for HEAD probes. */
function installMock(zones: Record<string, Zone>): void {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const parsed = new URL(url);
		const qName = parsed.searchParams.get('name');
		const qType = parsed.searchParams.get('type');
		if (qName !== null && qType !== null) {
			const name = qName.toLowerCase().replace(/\.$/, '');
			const type = CODE_TYPE[qType.toUpperCase()];
			const records = type ? zones[name]?.[type] : undefined;
			if (records && type) return Promise.resolve(dohAnswer(name, type, records));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('rdap')) {
			const body = {
				objectClassName: 'domain',
				entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Registrar Inc']]] }],
			};
			return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/rdap+json' } }));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	});
}

const SEED = 'debugpoint.com';
/** A Hostinger tenant with live web + mail — the shape a squatter on the seed's platform takes. */
const HOSTINGER_ZONE: Zone = { NS: HOSTINGER_NS.map((h) => `${h}.`), A: ['192.0.2.10'], MX: ['10 mx1.hostinger.com.'] };
const DMARC_REJECT: Zone = { TXT: ['v=DMARC1; p=reject'] };

describe('checkLookalikes — debugpoint.com → debugpoin.com on the same Hostinger pair (#939)', () => {
	it('does not attribute the candidate to the seed and keeps the uncapped threat observation', async () => {
		installMock({
			[SEED]: HOSTINGER_ZONE,
			[`_dmarc.${SEED}`]: DMARC_REJECT,
			'debugpoin.com': HOSTINGER_ZONE,
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes(SEED);

		const own = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'debugpoin.com');
		expect(own.length).toBeGreaterThan(0);
		expect(own.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(own.some((f) => f.metadata?.ownershipStrength === 'strong')).toBe(false);
		const attribution = own.find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		expect(attribution!.metadata?.ownershipVerdict).toBe('unattributed');
		expect(attribution!.metadata?.ownershipRationale).toContain('ns1.dns-parking.com');
		expect(attribution!.severity).toBe('info');
		// A mail-capable squatter on the seed's platform is counted, not spared
		// by the seed's hosting choice.
		const threat = own.find((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat).toBeDefined();
		expect(threat!.metadata?.ownershipVerdict).toBe('unattributed');
		// #264 calibration: MX present, web content reachable (HEAD 200), no
		// recent-registration signal (registrar-only RDAP) → `medium`.
		expect(threat!.severity).toBe('medium');

		const serialised = JSON.stringify(result.findings);
		expect(serialised).not.toContain('dedicated');
		expect(serialised).not.toContain('likely owned by same entity');
		expect(result.partial).not.toBe(true);
	});
});

// ---------------------------------------------------------------------------
// End-to-end — the enterprise-gated cost, pinned (corporate registrar udns pair, live 2026-09-09)
// ---------------------------------------------------------------------------

const CORP_REGISTRAR_SEED = 'natwest.com';
/** The seed's own defensive-style name on the enterprise-gated registrar, but mail-capable — the shape that now surfaces a threat observation. */
const CORP_REGISTRAR_ZONE_WITH_MX: Zone = {
	NS: CORP_REGISTRAR_UDNS.map((h) => `${h}.`),
	A: ['192.0.2.20'],
	MX: ['10 mx.natwest.example.'],
};

describe('checkLookalikes — natwest.com → natwes.com on the enterprise-gated registrar udns pair (#939, cost pinned)', () => {
	it('is unattributed with an uncapped medium threat observation, never owned_by_seed', async () => {
		installMock({
			[CORP_REGISTRAR_SEED]: CORP_REGISTRAR_ZONE_WITH_MX,
			[`_dmarc.${CORP_REGISTRAR_SEED}`]: DMARC_REJECT,
			'natwes.com': CORP_REGISTRAR_ZONE_WITH_MX,
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes(CORP_REGISTRAR_SEED);

		const own = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'natwes.com');
		expect(own.length).toBeGreaterThan(0);
		expect(own.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		const attribution = own.find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		expect(attribution!.metadata?.ownershipVerdict).toBe('unattributed');
		expect(attribution!.metadata?.ownershipRationale).toContain('udns1.cscdns.net');
		expect(attribution!.severity).toBe('info');
		// THE DISCLOSED CHANGE: before #939 this candidate was owned_by_seed and
		// the threat axis was spared; now it is counted at the #264 calibrated
		// severity (MX + reachable web → medium). If this is the customer's own
		// registration, that is a false positive the operator has accepted in
		// exchange for never capping a squatter's severity — see #949.
		const threat = own.find((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat).toBeDefined();
		expect(threat!.severity).toBe('medium');
		expect(threat!.metadata?.ownershipVerdict).toBe('unattributed');
	});
});

describe('checkShadowDomains — natwest.com → natwest.net on the enterprise-gated registrar udns pair (#939, cost pinned)', () => {
	it('clamps the variant to info — the owned-only "lacks DMARC" rung is no longer reachable for it', async () => {
		installMock({
			[CORP_REGISTRAR_SEED]: CORP_REGISTRAR_ZONE_WITH_MX,
			[`_dmarc.${CORP_REGISTRAR_SEED}`]: DMARC_REJECT,
			// MX, no SPF, no DMARC: the top rung of the OWNED ladder.
			'natwest.net': CORP_REGISTRAR_ZONE_WITH_MX,
		});
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains(CORP_REGISTRAR_SEED);

		const net = result.findings.filter((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'natwest.net');
		expect(net.length).toBeGreaterThan(0);
		// THE DISCLOSED CHANGE: while wrongly owned_by_seed this variant carried
		// the real high "fully spoofable … Likely same owner" finding. Now it is
		// info: if natwest.net really is the customer's, a true positive about
		// its DMARC posture is lost here (it is still reported when the customer
		// scans natwest.net directly). Accepted per #937's rule; see #949.
		for (const f of net) {
			expect(f.metadata?.ownershipVerdict).toBe('unattributed');
			expect(f.severity).toBe('info');
		}
		expect(JSON.stringify(result.findings)).not.toContain('Likely same owner');
	});
});

describe('checkShadowDomains — debugpoint.com → debugpoint.net on the same Hostinger pair (#939)', () => {
	it('marks the .net variant unattributed (info-capped) — never "Likely same owner"', async () => {
		installMock({
			[SEED]: HOSTINGER_ZONE,
			[`_dmarc.${SEED}`]: DMARC_REJECT,
			'debugpoint.net': HOSTINGER_ZONE,
		});
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains(SEED);

		const net = result.findings.filter((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'debugpoint.net');
		expect(net.length).toBeGreaterThan(0);
		for (const f of net) {
			expect(f.metadata?.ownershipVerdict).not.toBe('owned_by_seed');
			expect(f.severity).toBe('info');
		}
		expect(net.some((f) => f.metadata?.ownershipVerdict === 'unattributed')).toBe(true);
		const serialised = JSON.stringify(result.findings);
		expect(serialised).not.toContain('Likely same owner');
		expect(serialised).not.toContain('dedicated nameservers');
	});
});
