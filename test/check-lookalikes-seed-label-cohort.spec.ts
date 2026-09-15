// SPDX-License-Identifier: BUSL-1.1

/**
 * #974 reopened — the step-5c corroborator (`seed_infrastructure_match`) needs
 * the candidate's A AND MX sets to equal the SEED's, and the live cohort never
 * meets that: every `ltmcguinness.{com,net,co,io,ai}` variant sits on the seed's
 * A address, but on an agency's NS and a hosting provider's antispam MX, while
 * the seed routes mail elsewhere. Worse, `.net`/`.co`/`.io`/`.ai` were never
 * even generated for a `.co.nz` seed, so the cohort was invisible.
 *
 * Fix under test:
 *  - `generateTldVariants` lane — the exact seed label under the common gTLDs
 *    and the seed's ccTLD family (pinned in `test/lookalike-analysis.spec.ts`);
 *  - step 5d `seed_label_cohort`: candidate A == seed's non-empty A, and 2+
 *    OTHER exact-label variants share its identical A, NS and MX sets on
 *    non-platform NS → `unattributed` (never `owned_by_seed`), severity
 *    unchanged, "confirm ownership before blocking or takedown" advice, and
 *    `attributionConfidence: 'corroborated'` (two agreeing signals).
 *
 * #974 large-cohort exception (SQ-24, from SQ-23's live finding): the LIVE
 * `ltmcguinness` cohort sits on `ns1/ns2.siteground.net` — a
 * `SHARED_NS_APEXES` platform — so the non-platform-NS condition above
 * rejected it outright and the whole cohort was live-missed a second time.
 * `SEED_LABEL_COHORT_SHARED_NS_MIN` (5) waives that exclusion only when the
 * exact-label cohort has 5+ members (siblings plus the candidate); below 5,
 * shared-NS candidates behave exactly as before (the #929 guard against an
 * accidental small grouping of unrelated platform tenants).
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import type { LabelCohortMember } from '../src/lib/ownership-attribution';
import type { RegistrationState } from '../src/lib/registration-state';

const { restore } = setupFetchMock();
afterEach(() => restore());

const SEED = 'example.co.nz';
const SEED_NS = ['ns1.seed-dns.example', 'ns2.seed-dns.example'];
const SEED_A = ['203.0.113.10'];
const SEED_MX = ['mail.seed-mailhost.example'];
const AGENCY_NS = ['ns1.agency-hosting.example', 'ns2.agency-hosting.example'];
const ANTISPAM_MX = ['mx10.antispam.mailhost.example', 'mx20.antispam.mailhost.example', 'mx30.antispam.mailhost.example'];
/** Namecheap's registrar-default BasicDNS pair: a `SHARED_NS_APEXES` platform set. */
const PLATFORM_NS = ['dns1.registrar-servers.com', 'dns2.registrar-servers.com'];
const COHORT = ['example.com', 'example.net', 'example.co', 'example.io', 'example.ai'];

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

function member(domain: string, over: Partial<LabelCohortMember> = {}): LabelCohortMember {
	return { domain, a: SEED_A, ns: AGENCY_NS, mx: ANTISPAM_MX, ...over };
}

async function classify(candidateDomain: string, cohort: LabelCohortMember[], over: { ns?: string[]; a?: string[]; mx?: string[] } = {}) {
	const { classifyOwnership } = await import('../src/lib/ownership-attribution');
	const { isSharedNsHost } = await import('../src/tenants/discovery/shared-ns-hosts');
	return classifyOwnership({
		seedDomain: SEED,
		seedNs: SEED_NS,
		candidateDomain,
		registration: registered(over.ns ?? AGENCY_NS),
		isSharedNsHost,
		candidateA: over.a ?? SEED_A,
		candidateMx: over.mx ?? ANTISPAM_MX,
		seedA: SEED_A,
		seedMx: SEED_MX,
		labelCohort: cohort,
	});
}

describe('classifyOwnership step 5d — seed label cohort (#974 reopened)', () => {
	it('the ltmcguinness cohort shape is unattributed with seed_label_cohort, never owned_by_seed', async () => {
		const a = await classify(
			'example.com',
			COHORT.map((d) => member(d)),
		);
		expect(a.verdict).toBe('unattributed');
		expect(a.signals).toEqual(['seed_label_cohort']);
		expect(a.rationale).toContain('203.0.113.10');
		expect(a.rationale).toContain('example.net');
		expect(a.rationale).not.toContain('no ownership signal links it');
	});

	it('exactly 2 matched siblings (3 variants) is enough; 1 sibling is not', async () => {
		expect((await classify('example.com', [member('example.net'), member('example.io')])).verdict).toBe('unattributed');
		const one = await classify('example.com', [member('example.net')]);
		expect(one.verdict).toBe('third_party');
		expect(one.signals).toEqual(['distinct_infrastructure']);
	});

	it('a single exact-label variant sharing only the seed A stays third_party', async () => {
		const a = await classify('example.com', [member('example.com')]);
		expect(a.verdict).toBe('third_party');
	});

	it('a 3-variant cohort on a SHARED_NS_APEXES platform stays third_party', async () => {
		const cohort = ['example.com', 'example.net', 'example.io'].map((d) => member(d, { ns: PLATFORM_NS }));
		const a = await classify('example.com', cohort, { ns: PLATFORM_NS });
		expect(a.verdict).toBe('third_party');
		expect(a.signals).not.toContain('seed_label_cohort');
	});

	it('siblings must match the complete NS set, the MX set and the A set exactly', async () => {
		const siblings = (over: Partial<LabelCohortMember>) => [member('example.net', over), member('example.io', over)];
		expect((await classify('example.com', siblings({ ns: [AGENCY_NS[0]] }))).verdict).toBe('third_party');
		expect((await classify('example.com', siblings({ mx: ANTISPAM_MX.slice(1) }))).verdict).toBe('third_party');
		expect((await classify('example.com', siblings({ a: [...SEED_A, '198.51.100.7'] }))).verdict).toBe('third_party');
	});

	it('the candidate A must equal the seed A even when the siblings agree with each other', async () => {
		const other = ['198.51.100.7'];
		const cohort = COHORT.map((d) => member(d, { a: other }));
		expect((await classify('example.com', cohort, { a: other })).verdict).toBe('third_party');
	});

	it('a typosquat never qualifies — neither as the candidate nor as a sibling', async () => {
		const typoCohort = ['exampel.com', 'exampel.net', 'exampel.io'].map((d) => member(d));
		expect((await classify('exampel.com', typoCohort)).verdict).toBe('third_party');
		const typoSiblings = [member('exampel.net'), member('examp1e.io')];
		expect((await classify('example.com', typoSiblings)).verdict).toBe('third_party');
	});

	it('the seed ccTLD family counts as exact-label variants, but the seed apex itself does not', async () => {
		expect((await classify('example.com', [member('example.nz'), member('example.org.nz')])).verdict).toBe('unattributed');
		expect((await classify('example.com', [member(SEED), member('example.net')])).verdict).toBe('third_party');
	});

	it('fails closed when the candidate MX leg was not measured', async () => {
		const { classifyOwnership } = await import('../src/lib/ownership-attribution');
		const { isSharedNsHost } = await import('../src/tenants/discovery/shared-ns-hosts');
		const a = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'example.com',
			registration: registered(AGENCY_NS),
			isSharedNsHost,
			candidateA: SEED_A,
			seedA: SEED_A,
			seedMx: SEED_MX,
			labelCohort: COHORT.map((d) => member(d)),
		});
		expect(a.verdict).toBe('third_party');
	});
});

describe('classifyOwnership step 5d — large-cohort exception to the shared-NS exclusion (#974)', () => {
	/** The live shape: 6 exact-label TLD variants, all on a SHARED_NS_APEXES platform. */
	const SITEGROUND_SIX = [...COHORT, 'example.nz'].map((d) => member(d, { ns: PLATFORM_NS }));

	it('a 6-member exact-label cohort on a shared-tenant platform NS is unattributed via seed_label_cohort', async () => {
		const a = await classify('example.com', SITEGROUND_SIX, { ns: PLATFORM_NS });
		expect(a.verdict).toBe('unattributed');
		expect(a.signals).toEqual(['seed_label_cohort']);
		expect(a.rationale).toContain('example.net');
	});

	it('every member of the 6-variant cohort resolves unattributed, never owned_by_seed', async () => {
		for (const domain of [...COHORT, 'example.nz']) {
			const a = await classify(domain, SITEGROUND_SIX, { ns: PLATFORM_NS });
			expect(a.verdict, domain).toBe('unattributed');
			expect(a.signals, domain).toEqual(['seed_label_cohort']);
		}
	});

	it('a 4-member cohort on the same platform stays third_party — below the large-cohort threshold, the #929 guard still applies', async () => {
		const four = SITEGROUND_SIX.slice(0, 4); // candidate + 3 siblings = 4 members
		const a = await classify('example.com', four, { ns: PLATFORM_NS });
		expect(a.verdict).toBe('third_party');
		expect(a.signals).not.toContain('seed_label_cohort');
	});

	it('exactly 5 members waives the exclusion; 4 does not', async () => {
		const five = SITEGROUND_SIX.slice(0, 5); // candidate + 4 siblings = 5 members
		expect((await classify('example.com', five, { ns: PLATFORM_NS })).verdict).toBe('unattributed');
		const four = SITEGROUND_SIX.slice(0, 4);
		expect((await classify('example.com', four, { ns: PLATFORM_NS })).verdict).toBe('third_party');
	});

	it('a 6-member cohort whose A does not equal the seed A stays third_party — the exception never bypasses the A check', async () => {
		const otherA = ['198.51.100.7'];
		const cohort = SITEGROUND_SIX.map((m) => ({ ...m, a: otherA }));
		const a = await classify('example.com', cohort, { ns: PLATFORM_NS, a: otherA });
		expect(a.verdict).toBe('third_party');
	});

	it('the large-cohort exception never yields owned_by_seed, whatever the cohort size', async () => {
		const a = await classify('example.com', SITEGROUND_SIX, { ns: PLATFORM_NS });
		expect(a.verdict).not.toBe('owned_by_seed');
	});
});

// ---------------------------------------------------------------------------
// End-to-end through checkLookalikes()
// ---------------------------------------------------------------------------

type RecordName = 'NS' | 'A' | 'MX';
const TYPE_CODE: Record<RecordName, number> = { NS: 2, A: 1, MX: 15 };
const CODE_TYPE: Record<string, RecordName> = { '2': 'NS', NS: 'NS', '1': 'A', A: 'A', '15': 'MX', MX: 'MX' };
type Zone = Partial<Record<RecordName, string[]>>;

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
			if (records && type) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: TYPE_CODE[type] }],
						records.map((data) => ({ name, type: TYPE_CODE[type], TTL: 300, data })),
					),
				);
			}
			return Promise.resolve(createDohResponse([], []));
		}
		return Promise.resolve(new Response('', { status: 404 }));
	});
}

const mxRecords = (hosts: string[]) => hosts.map((h, i) => `${(i + 1) * 10} ${h}.`);
const SEED_ZONE: Zone = { NS: SEED_NS.map((h) => `${h}.`), A: SEED_A, MX: mxRecords(SEED_MX) };
const variantZone = (ns: string[]): Zone => ({ NS: ns.map((h) => `${h}.`), A: SEED_A, MX: mxRecords(ANTISPAM_MX) });

async function runFor(variants: string[], ns: string[] = AGENCY_NS) {
	installMock({ [SEED]: SEED_ZONE, ...Object.fromEntries(variants.map((d) => [d, variantZone(ns)])) });
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	const result = await checkLookalikes(SEED);
	const own = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'example.com');
	return {
		result,
		attribution: own.find((f) => f.metadata?.findingAxis === 'attribution'),
		threat: own.find((f) => f.metadata?.findingAxis === 'threat_observation'),
	};
}

describe('checkLookalikes — exact-label TLD cohort on the seed A (#974 reopened)', () => {
	it('generates and resolves the whole cohort, and reports each variant unattributed with confirm-first advice', async () => {
		const { result, attribution, threat } = await runFor(COHORT);
		for (const variant of COHORT) {
			const row = result.findings.find((f) => f.metadata?.lookalikeDomain === variant && f.metadata?.findingAxis === 'attribution');
			expect(row?.metadata?.ownershipVerdict, variant).toBe('unattributed');
		}
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(attribution!.severity).toBe('info');
		expect(attribution!.metadata?.attributionConfidence).toBe('corroborated');
		expect(attribution!.metadata?.ownershipRationale).toContain('exact-label variants');
		expect(threat).toBeDefined();
		expect(threat!.detail).toContain('Do NOT block it at the gateway or report it for takedown before confirming ownership');
		expect(threat!.detail).not.toContain('does not appear to belong to the scanned organisation');
	});

	it('severity is unchanged: the cohort threat observation carries the same severity as a lone third_party variant', async () => {
		const cohort = await runFor(COHORT);
		const lone = await runFor(['example.com']);
		expect(lone.attribution!.metadata?.ownershipVerdict).toBe('third_party');
		expect(cohort.threat!.severity).toBe(lone.threat!.severity);
	});

	it('a single exact-label variant sharing only the seed A stays third_party with the takedown advice', async () => {
		const { attribution, threat } = await runFor(['example.com']);
		expect(attribution!.metadata?.ownershipVerdict).toBe('third_party');
		expect(attribution!.metadata?.attributionConfidence).toBe('single_signal');
		expect(threat!.detail).toContain('block or quarantine mail bearing that name at the gateway');
	});

	it('a 3-variant cohort on a SHARED_NS_APEXES platform stays third_party', async () => {
		const { attribution, threat } = await runFor(['example.com', 'example.net', 'example.io'], PLATFORM_NS);
		expect(attribution!.metadata?.ownershipVerdict).toBe('third_party');
		expect(threat!.detail).toContain('block or quarantine mail bearing that name at the gateway');
	});
});

describe('checkLookalikes — large-cohort exception to the shared-NS exclusion (#974)', () => {
	/** The live shape (SQ-24): 6 exact-label TLD variants, all on siteground.net (`SHARED_NS_APEXES`). */
	const SIX_VARIANTS = [...COHORT, 'example.nz'];

	it('a 6-variant cohort on a SHARED_NS_APEXES platform is unattributed with confirm-first advice, not takedown', async () => {
		const { result, attribution, threat } = await runFor(SIX_VARIANTS, PLATFORM_NS);
		for (const variant of SIX_VARIANTS) {
			const row = result.findings.find((f) => f.metadata?.lookalikeDomain === variant && f.metadata?.findingAxis === 'attribution');
			expect(row?.metadata?.ownershipVerdict, variant).toBe('unattributed');
		}
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(attribution!.metadata?.attributionConfidence).toBe('corroborated');
		expect(threat!.detail).toContain('Do NOT block it at the gateway or report it for takedown before confirming ownership');
	});

	it('a 4-variant cohort on the same platform stays third_party with takedown advice — below the large-cohort threshold', async () => {
		const { attribution, threat } = await runFor(SIX_VARIANTS.slice(0, 4), PLATFORM_NS);
		expect(attribution!.metadata?.ownershipVerdict).toBe('third_party');
		expect(threat!.detail).toContain('block or quarantine mail bearing that name at the gateway');
	});
});
