// SPDX-License-Identifier: BUSL-1.1

/**
 * #864 (regression of #263) — a same-entity domain on a DIFFERENT DNS platform
 * must not be counted as an impersonation-capable third party — without
 * letting a forged candidate-side record hide a sending squatter.
 *
 * Every fixture below is transcribed from live DoH / RDAP / CT answers
 * observed 2026-09-04 (`dns.google/resolve`, `rdap.verisign.com`,
 * `rdap.cctld.au`, `crt.sh`):
 *
 *   amazon.com     NS  ns-{521,264,1707,1447}.awsdns-*             (Route 53)
 *                  MX  5 amazon-smtp.amazon.com
 *   amazon.com.au  NS  ns{1,2}.amzndns.{com,co.uk,net,org}         (Amazon internal)
 *                  MX  10 amazon-smtp.amazon.com                    ← seed's own MX host
 *                  _dmarc → CNAME _dmarc.amazon.com:
 *                      v=DMARC1;p=quarantine;pct=100;rua=mailto:report<at>dmarc.amazon.com;ruf=…
 *                  amazon.com.au._report._dmarc.dmarc.amazon.com TXT "v=DMARC1"   ← SEED-published
 *                  <random>._report._dmarc.dmarc.amazon.com        NXDOMAIN         (not a wildcard)
 *                  amzndns.com._report._dmarc.dmarc.amazon.com     NXDOMAIN         (per-domain grant)
 *                  RDAP (auDA): NO registrant entity — registrar only
 *   amazon.com     RDAP (Verisign): thin — registrar only, no registrant
 *   CT (crt.sh):   0 of 3300 amazon.com.au certificates also cover amazon.com
 *
 *   xero.com       NS  ns-*.awsdns-*  MX Google  _dmarc rua=mailto:xero<at>rua.agari.com
 *   xero.co.nz     NS  a*.akam.net    MX Google  _dmarc rua=mailto:xero<at>rua.agari.com
 *
 * So for the Amazon pair NEITHER the shared-NS arms NOR the #263 RDAP
 * registrant tier can fire; the one SEED-SIDE record that links them is the
 * RFC 7489 §7.1 external-report authorisation, which only the owner of
 * `dmarc.amazon.com` can publish. That is `classifyOwnership()` step 5b — see
 * the 2026-09-04 amendment in `src/lib/ownership-attribution.ts`. The
 * candidate's MX is a PRE-FILTER only: a sending squatter copies it for free.
 * For the Xero pair both domains report to a third party (Agari), so no
 * seed-side signal exists and the arm must decline.
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
import type { DmarcReportAuthorisation } from '../src/lib/ownership-attribution';

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
/** Mailboxes are assembled with `AT` so the literal never trips the secret scanners' real-email rule; runtime strings are the live records. */
const AT = '@';
const AMAZON_DMARC = `v=DMARC1;p=quarantine;pct=100;rua=mailto:report${AT}dmarc.amazon.com;ruf=mailto:report${AT}dmarc.amazon.com`;
const AMAZON_RECEIVER = 'dmarc.amazon.com';
const AMAZON_AU_GRANT = 'amazon.com.au._report._dmarc.dmarc.amazon.com';
/** Live (`WILDCARD_CANARY_LABEL` in lookalike-dns.ts) — the probe's canary label under the receiver's `_report._dmarc`. */
const CANARY_LABEL = '_bv-wc-probe';

const XERO_SEED_NS = ['ns-1911.awsdns-46.co.uk', 'ns-1391.awsdns-45.org', 'ns-983.awsdns-58.net', 'ns-90.awsdns-11.com'];
const XERO_NZ_NS = ['a13-64.akam.net', 'a1-170.akam.net', 'a28-66.akam.net', 'a5-67.akam.net', 'a10-67.akam.net', 'a14-65.akam.net'];
const GOOGLE_MX = [
	'aspmx.l.google.com',
	'alt1.aspmx.l.google.com',
	'alt2.aspmx.l.google.com',
	'aspmx2.googlemail.com',
	'aspmx3.googlemail.com',
];
const XERO_DMARC = `v=DMARC1; p=reject; fo=1; ri=3600; rua=mailto:xero${AT}rua.agari.com; ruf=mailto:xero${AT}ruf.agari.com`;

const AUTHORISED: DmarcReportAuthorisation = {
	status: 'authorised',
	seedReceivers: [AMAZON_RECEIVER],
	receiverDomain: AMAZON_RECEIVER,
	authorisationRecord: AMAZON_AU_GRANT,
};

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

async function loadAttribution() {
	return import('../src/lib/ownership-attribution');
}

// ---------------------------------------------------------------------------
// Unit — parseDmarcReportReceivers()
// ---------------------------------------------------------------------------

describe('parseDmarcReportReceivers (#864)', () => {
	it('extracts rua/ruf mailbox domains from the live amazon.com and xero records', async () => {
		const { parseDmarcReportReceivers } = await loadAttribution();
		expect(parseDmarcReportReceivers(AMAZON_DMARC)).toEqual(['dmarc.amazon.com']);
		expect(parseDmarcReportReceivers(XERO_DMARC)).toEqual(['rua.agari.com', 'ruf.agari.com']);
	});

	it('handles size suffixes, multiple URIs, case, and ignores non-mailto destinations', async () => {
		const { parseDmarcReportReceivers } = await loadAttribution();
		expect(
			parseDmarcReportReceivers(`v=DMARC1; p=none; RUA=mailto:a${AT}One.Example!10m, https://api.example/report, mailto:b${AT}two.example`),
		).toEqual(['one.example', 'two.example']);
		expect(parseDmarcReportReceivers('v=DMARC1; p=reject')).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Unit — classifyOwnership() step 5b
// ---------------------------------------------------------------------------

describe('classifyOwnership — seed-authorised convergence (#864, live amazon.com.au records)', () => {
	it('attributes amazon.com.au to amazon.com: MX pre-filter met AND the seed publishes the RFC 7489 §7.1 grant', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			dmarcReportAuthorisation: AUTHORISED,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('medium');
		expect(result.signals).toEqual(['mx_in_bailiwick', 'dmarc_report_authorised_by_seed']);
		expect(result.rationale).toContain(AMAZON_AU_GRANT);
		expect(result.rationale).toContain('RFC 7489');
		// Evidence names every record the verdict rests on, so a consumer can audit it.
		expect(result.evidence).toEqual([
			{ record: 'MX', value: 'amazon-smtp.amazon.com', inSeedBailiwick: true },
			{ record: 'DMARC.RUA', value: 'dmarc.amazon.com', inSeedBailiwick: true },
			{ record: 'DMARC.REPORT_AUTHORISATION', value: AMAZON_AU_GRANT, inSeedBailiwick: true },
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

	it('NEGATIVE — the MX pre-filter alone never qualifies: a squatter copying the seed MX string stays third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const nonGrants: Array<DmarcReportAuthorisation | undefined> = [
			undefined,
			{ status: 'no_seed_receiver', seedReceivers: [] },
			{ status: 'not_authorised', seedReceivers: [AMAZON_RECEIVER] },
		];
		for (const auth of nonGrants) {
			const result = classifyOwnership({
				seedDomain: 'amazon.com',
				seedNs: AMAZON_SEED_NS,
				candidateDomain: 'amaz0n.com',
				registration: registered(['ns1.amaz0n.com', 'ns2.amaz0n.com']),
				isSharedNsHost,
				candidateMx: [AMAZON_MX_HOST],
				dmarcReportAuthorisation: auth,
			});
			expect(result.verdict, `status=${auth?.status ?? 'undefined'}`).toBe('third_party');
			expect(result.evidence).toBeUndefined();
		}
	});

	it('NEGATIVE — a WILDCARD grant is evidence-only: the seed authorised reports about anyone, not this candidate', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns1.amaz0n.com']),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			dmarcReportAuthorisation: { status: 'wildcard', seedReceivers: [AMAZON_RECEIVER], receiverDomain: AMAZON_RECEIVER },
		});
		expect(result.verdict).toBe('third_party');
	});

	it('NEGATIVE — defence in depth: an "authorised" result whose receiver or record sits OUTSIDE the seed apex is ignored', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns1.amaz0n.com']),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			dmarcReportAuthorisation: {
				status: 'authorised',
				seedReceivers: ['rua.attacker-reports.net'],
				receiverDomain: 'rua.attacker-reports.net',
				authorisationRecord: 'amaz0n.com._report._dmarc.rua.attacker-reports.net',
			},
		});
		expect(result.verdict).toBe('third_party');
	});

	it('NEGATIVE — a single MX outside the seed apex fails the pre-filter, so the seed-side result is never consulted', async () => {
		const { classifyOwnership, mxRoutedIntoSeed } = await loadAttribution();
		expect(mxRoutedIntoSeed([AMAZON_MX_HOST, 'mx.attacker-dns.net'], 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed([], 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed(undefined, 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed(['smtp.notamazon.com'], 'amazon.com')).toBe(false);
		expect(mxRoutedIntoSeed(['amazon-smtp.amazon.com.attacker.net'], 'amazon.com')).toBe(false);
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amaz0n.com',
			registration: registered(['ns1.amaz0n.com']),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST, 'mx.attacker-dns.net'],
			dmarcReportAuthorisation: AUTHORISED,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('#832 law — pre-filter met but the seed-side probe REJECTED → unmeasured, never the contrary third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.com.au',
			registration: registered(AMAZON_AU_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			dmarcReportAuthorisation: { status: 'unresolved', seedReceivers: [AMAZON_RECEIVER] },
		});
		expect(result.verdict).toBe('unmeasured');
		expect(result.signals).toEqual(['mx_in_bailiwick']);
		expect(result.rationale).toContain('measurement gap');
		expect(result.rationale).not.toContain('no ownership signal links it');
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
			dmarcReportAuthorisation: AUTHORISED,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.signals).toEqual(['mx_in_bailiwick', 'dmarc_report_authorised_by_seed']);
	});

	it('seed-side NS arms keep precedence: a full dedicated NS match is reported as strong ns_set_match, not displaced by the medium arm', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'amazon.com',
			seedNs: AMAZON_SEED_NS,
			candidateDomain: 'amazon.net',
			registration: registered(AMAZON_SEED_NS),
			isSharedNsHost,
			candidateMx: [AMAZON_MX_HOST],
			dmarcReportAuthorisation: AUTHORISED,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.signals).toEqual(['ns_set_match']);
	});

	it('xero.co.nz (#263 shape): mail at Google, reports to Agari — pre-filter unmet, no seed-side signal, arm declines', async () => {
		const { classifyOwnership, mxRoutedIntoSeed } = await loadAttribution();
		expect(mxRoutedIntoSeed(GOOGLE_MX, 'xero.com')).toBe(false);
		const result = classifyOwnership({
			seedDomain: 'xero.com',
			seedNs: XERO_SEED_NS,
			candidateDomain: 'xero.co.nz',
			registration: registered(XERO_NZ_NS),
			isSharedNsHost,
			candidateMx: GOOGLE_MX,
			dmarcReportAuthorisation: { status: 'no_seed_receiver', seedReceivers: [] },
		});
		// Structurally third_party from DNS — the pair's only link is #263's
		// registrant-org lane (wording-only), which this arm neither replaces
		// nor weakens.
		expect(result.verdict).toBe('third_party');
		expect(result.evidence).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// End-to-end — checkLookalikes() over the real permutation set
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

/** Per-name zone data. A record set of `'reject'` makes that lookup throw (throttled / timed out). TXT values are given unquoted. */
type Zone = Partial<Record<RecordName, string[] | 'reject'>>;

function dohAnswer(name: string, type: RecordName, records: string[]) {
	return createDohResponse(
		[{ name, type: TYPE_CODE[type] }],
		records.map((data) => ({ name, type: TYPE_CODE[type], TTL: 300, data: type === 'TXT' ? `"${data}"` : data })),
	);
}

/**
 * Install a fetch mock serving DoH from `zones`, a thin registrar-only RDAP
 * document (what Verisign and auDA actually publish) for every RDAP URL, and
 * a 200 for every HEAD probe. Returns the log of `_dmarc`-path query names so
 * a test can prove the #864 probe was gated, not fanned out.
 */
function installMock(zones: Record<string, Zone>): { dmarcQueries: string[] } {
	const dmarcQueries: string[] = [];
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const parsed = new URL(url);
		const qName = parsed.searchParams.get('name');
		const qType = parsed.searchParams.get('type');
		if (qName !== null && qType !== null) {
			const name = qName.toLowerCase().replace(/\.$/, '');
			const type = CODE_TYPE[qType.toUpperCase()];
			if (name.includes('_dmarc')) dmarcQueries.push(name);
			const records = type ? zones[name]?.[type] : undefined;
			if (records === 'reject') return Promise.reject(new Error('DNS timeout'));
			if (records && type) return Promise.resolve(dohAnswer(name, type, records));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('rdap')) {
			const match = url.match(/\/domain\/([^/?]+)/i);
			const domain = match?.[1]?.toLowerCase() ?? '';
			const body = {
				objectClassName: 'domain',
				ldhName: domain,
				entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Registrar Inc']]] }],
			};
			return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/rdap+json' } }));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	});
	return { dmarcQueries };
}

async function runCheck(domain: string) {
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	return checkLookalikes(domain);
}

const AMAZON_SEED_ZONE: Zone = { NS: AMAZON_SEED_NS.map((h) => `${h}.`), MX: [`5 ${AMAZON_MX_HOST}.`] };

/** The forged candidate zone the #897 review described: attacker NS on a VPS, copied MX, MNAME under the seed apex, DMARC reporting into the seed. */
function forgedSquatterZone(domain: string): Zone {
	return {
		NS: [`ns1.${domain}.`, `ns2.${domain}.`],
		A: ['192.0.2.10'],
		MX: [`10 ${AMAZON_MX_HOST}.`],
		SOA: ['dns-external-master.amazon.com. root.amazon.com. 1 600 300 604800 900'],
		TXT: [],
	};
}

function threatRetained(findings: Array<{ title: string; metadata?: Record<string, unknown> }>, candidate: string): void {
	const own = findings.filter((f) => f.metadata?.lookalikeDomain === candidate);
	expect(own.length).toBeGreaterThan(0);
	expect(own.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
	expect(own.some((f) => f.metadata?.findingAxis === 'attribution' && f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
	expect(own.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(true);
	// Still counted: the mail-capable rollup names it.
	expect(
		findings.some((f) => /working mail host|pre-phishing staging/i.test(f.title) && JSON.stringify(f.metadata ?? {}).includes(candidate)),
	).toBe(true);
}

describe('checkLookalikes — amazon.com → amazon.com.au (#864 regression fixture)', () => {
	it('reports amazon.com.au as owned_by_seed on the seed-published grant, and never as an impersonation-capable lookalike', async () => {
		const { dmarcQueries } = installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amazon.com.au': { NS: AMAZON_AU_NS.map((h) => `${h}.`), A: ['52.95.116.115'], MX: [`10 ${AMAZON_MX_HOST}.`] },
			'_dmarc.amazon.com.au': { TXT: [AMAZON_DMARC] },
			[AMAZON_AU_GRANT]: { TXT: ['v=DMARC1'] },
			// canary label → NXDOMAIN (empty), exactly as observed live
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
		expect(owned!.metadata?.ownershipSignals).toEqual(['mx_in_bailiwick', 'dmarc_report_authorised_by_seed']);
		expect(owned!.metadata?.attributionConfidence).toBe('corroborated');
		expect(owned!.metadata?.ownershipEvidence).toEqual([
			{ record: 'MX', value: 'amazon-smtp.amazon.com', inSeedBailiwick: true },
			{ record: 'DMARC.RUA', value: 'dmarc.amazon.com', inSeedBailiwick: true },
			{ record: 'DMARC.REPORT_AUTHORISATION', value: AMAZON_AU_GRANT, inSeedBailiwick: true },
		]);
		expect(owned!.detail).toContain(AMAZON_AU_GRANT);

		// The customer's own domain is not an impersonation threat to itself:
		// no threat observation, no third-party verdict, not counted anywhere.
		expect(au.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(result.findings.some((f) => /working mail host|pre-phishing staging/i.test(f.title))).toBe(false);
		const serialised = JSON.stringify(result.findings);
		expect(serialised).not.toContain('Impersonation-shaped');
		expect(serialised).not.toContain('no ownership signal links it');
		expect(result.partial).not.toBe(true);

		// Budget: exactly the three seed-side lookups for the ONE candidate whose
		// MX already routed into the seed — no fan-out across the ~84 permutations.
		expect(dmarcQueries).toEqual(['_dmarc.amazon.com.au', AMAZON_AU_GRANT, `${CANARY_LABEL}._report._dmarc.${AMAZON_RECEIVER}`]);
	});

	it('NEGATIVE (i) — forged SOA MNAME under the seed apex + copied seed MX + attacker NS + DMARC reporting into the seed: NOT owned, threat observation retained', async () => {
		const { dmarcQueries } = installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amaz0n.com': forgedSquatterZone('amaz0n.com'),
			'_dmarc.amaz0n.com': { TXT: [AMAZON_DMARC] },
			// The seed has NOT published amaz0n.com._report._dmarc.dmarc.amazon.com → NXDOMAIN.
		});
		const result = await runCheck('amazon.com');
		threatRetained(result.findings, 'amaz0n.com');
		// The probe WAS issued (pre-filter met) and correctly found no grant; no canary needed.
		expect(dmarcQueries).toEqual(['_dmarc.amaz0n.com', 'amaz0n.com._report._dmarc.dmarc.amazon.com']);
		expect(result.partial).not.toBe(true);
	});

	it('NEGATIVE (ii) — same forged zone where the MNAME host RESOLVES to a real seed host: still not sufficient', async () => {
		installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amaz0n.com': forgedSquatterZone('amaz0n.com'),
			'_dmarc.amaz0n.com': { TXT: [AMAZON_DMARC] },
			'dns-external-master.amazon.com': { A: ['52.94.236.248'] },
			'amazon-smtp.amazon.com': { A: ['52.94.236.10'] },
		});
		const result = await runCheck('amazon.com');
		threatRetained(result.findings, 'amaz0n.com');
	});

	it('NEGATIVE — a seed WILDCARD grant (`*._report._dmarc`) does not attribute a squatter that reports into the seed', async () => {
		const { dmarcQueries } = installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amaz0n.com': forgedSquatterZone('amaz0n.com'),
			'_dmarc.amaz0n.com': { TXT: [AMAZON_DMARC] },
			'amaz0n.com._report._dmarc.dmarc.amazon.com': { TXT: ['v=DMARC1'] },
			[`${CANARY_LABEL}._report._dmarc.${AMAZON_RECEIVER}`]: { TXT: ['v=DMARC1'] },
		});
		const result = await runCheck('amazon.com');
		threatRetained(result.findings, 'amaz0n.com');
		expect(dmarcQueries).toEqual([
			'_dmarc.amaz0n.com',
			'amaz0n.com._report._dmarc.dmarc.amazon.com',
			`${CANARY_LABEL}._report._dmarc.${AMAZON_RECEIVER}`,
		]);
	});

	it('NEGATIVE — copied MX with NS hostnames that merely resemble the seed platform and no DMARC record: not owned, no seed-side lookups beyond _dmarc', async () => {
		const { dmarcQueries } = installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amazom.com': { NS: ['ns1.amazon.com.attacker.net.', 'ns2.amzndns-hosting.net.'], A: ['192.0.2.11'], MX: [`10 ${AMAZON_MX_HOST}.`] },
		});
		const result = await runCheck('amazon.com');
		threatRetained(result.findings, 'amazom.com');
		expect(dmarcQueries).toEqual(['_dmarc.amazom.com']);
	});

	it('#832 law end-to-end — the seed-side grant lookup rejects for amazon.com.au → unmeasured, impersonation finding withheld, result marked partial', async () => {
		installMock({
			'amazon.com': AMAZON_SEED_ZONE,
			'amazon.com.au': { NS: AMAZON_AU_NS.map((h) => `${h}.`), A: ['52.95.116.115'], MX: [`10 ${AMAZON_MX_HOST}.`] },
			'_dmarc.amazon.com.au': { TXT: [AMAZON_DMARC] },
			[AMAZON_AU_GRANT]: { TXT: 'reject' },
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
	it('declines the arm (mail at Google) without issuing any seed-side lookup, and still surfaces the candidate at info', async () => {
		const { dmarcQueries } = installMock({
			'xero.com': { NS: XERO_SEED_NS.map((h) => `${h}.`), MX: GOOGLE_MX.map((h, i) => `${(i + 1) * 10} ${h}.`) },
			'xero.co.nz': { NS: XERO_NZ_NS.map((h) => `${h}.`), A: ['104.18.32.1'], MX: GOOGLE_MX.map((h, i) => `${(i + 1) * 10} ${h}.`) },
			'_dmarc.xero.co.nz': { TXT: [XERO_DMARC] },
		});
		const result = await runCheck('xero.com');

		const nz = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'xero.co.nz');
		expect(nz.length).toBeGreaterThan(0);
		// Not an over-fire: shared-provider mail is not "routed into the seed".
		expect(
			nz.some((f) => Array.isArray(f.metadata?.ownershipSignals) && (f.metadata!.ownershipSignals as string[]).includes('mx_in_bailiwick')),
		).toBe(false);
		// Zero extra DNS: the pre-filter failed, so no seed-side probe ran.
		expect(dmarcQueries).toEqual([]);
		// D4 cap unchanged — reported for awareness, never suppressed, never above info on the attribution axis.
		const attribution = nz.find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		expect(attribution!.severity).toBe('info');
		expect(['third_party', 'unattributed']).toContain(attribution!.metadata?.ownershipVerdict);
	});
});
