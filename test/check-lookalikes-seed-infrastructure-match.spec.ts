// SPDX-License-Identifier: BUSL-1.1

/**
 * #974 (third recurrence of #263 → #864) — ownership attribution still read
 * NS non-overlap alone as "distinct infrastructure".
 *
 * Live shape (DoH, 2026-09-10): an SMB's brand-variant cohort sits on its web
 * agency's nameservers, while every variant resolves to the SEED's own A
 * address and publishes the seed's own MX set. `classifyOwnership()` ran
 * before the A/MX probe, so its terminal arm returned `third_party` "with its
 * own nameservers … no ownership signal links it", stamped `corroborated`, and
 * the threat finding advised gateway-blocking and takedown of the customer's
 * own domain.
 *
 * Fix under test:
 *  - step 5c: identical A set AND identical real-MX set → `unattributed`
 *    (`seed_infrastructure_match`). Never `owned_by_seed` — both records are
 *    candidate-published and copyable (Ruling A / #864 review) — and neither
 *    leg alone moves anything (a shared web IP or a multi-tenant mail provider
 *    is what an unrelated tenant looks like — #929's lesson for A/MX).
 *  - `attributionConfidence()` reports `single_signal`, not `corroborated`, for
 *    a non-owned verdict no second signal agrees with.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import type { RegistrationState } from '../src/lib/registration-state';

const { restore } = setupFetchMock();
afterEach(() => restore());

const SEED = 'example.co.nz';
const SEED_NS = ['ns1.registrar-dns.example', 'ns2.registrar-dns.example', 'ns3.registrar-dns.example'];
const AGENCY_NS = ['ns1.agency-hosting.example', 'ns2.agency-hosting.example'];
const SEED_A = ['203.0.113.10'];
const SEED_MX = ['mx10.antispam.mailhost.example', 'mx20.antispam.mailhost.example', 'mx30.antispam.mailhost.example'];

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

async function loadAttribution() {
	const mod = await import('../src/lib/ownership-attribution');
	const { isSharedNsHost } = await import('../src/tenants/discovery/shared-ns-hosts');
	const classify = (extra: { candidateA?: string[]; candidateMx?: string[]; seedA?: string[]; seedMx?: string[] }) =>
		mod.classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'example.com',
			registration: registered(AGENCY_NS),
			isSharedNsHost,
			...extra,
		});
	return { ...mod, classify };
}

describe('classifyOwnership step 5c — seed infrastructure match (#974)', () => {
	it('agency-NS candidate on the seed A set AND MX set is unattributed, not third_party — and never owned_by_seed', async () => {
		const { classify } = await loadAttribution();
		const a = classify({ candidateA: SEED_A, candidateMx: [...SEED_MX].reverse(), seedA: SEED_A, seedMx: SEED_MX });
		expect(a.verdict).toBe('unattributed');
		expect(a.signals).toEqual(['seed_infrastructure_match']);
		expect(a.rationale).toContain('203.0.113.10');
		expect(a.rationale).toContain('mx10.antispam.mailhost.example');
		expect(a.rationale).not.toContain('no ownership signal links it');
	});

	it('shared-provider MX alone (identical MX, different A) stays third_party', async () => {
		const { classify } = await loadAttribution();
		const mx = ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'];
		const a = classify({ candidateA: ['198.51.100.7'], candidateMx: mx, seedA: SEED_A, seedMx: mx });
		expect(a.verdict).toBe('third_party');
		expect(a.signals).toEqual(['distinct_infrastructure']);
	});

	it('shared web IP alone (identical A, different MX) stays third_party', async () => {
		const { classify } = await loadAttribution();
		const a = classify({ candidateA: SEED_A, candidateMx: ['mail.attacker.example'], seedA: SEED_A, seedMx: SEED_MX });
		expect(a.verdict).toBe('third_party');
	});

	it('an overlap is not identity: a candidate A superset of the seed set stays third_party', async () => {
		const { classify } = await loadAttribution();
		const a = classify({ candidateA: [...SEED_A, '198.51.100.7'], candidateMx: SEED_MX, seedA: SEED_A, seedMx: SEED_MX });
		expect(a.verdict).toBe('third_party');
	});

	it('fails closed when either side was not measured (empty seed A)', async () => {
		const { classify } = await loadAttribution();
		expect(classify({ candidateA: [], candidateMx: SEED_MX, seedA: [], seedMx: SEED_MX }).verdict).toBe('third_party');
		expect(classify({ candidateMx: SEED_MX, seedMx: SEED_MX }).verdict).toBe('third_party');
	});
});

describe('attributionConfidence — a one-signal verdict is not "corroborated" (#974)', () => {
	it('long label, no second signal → single_signal; a real corroborator → corroborated; short label → uncorroborated', async () => {
		const { attributionConfidence } = await loadAttribution();
		expect(attributionConfidence('third_party', 'example', false)).toBe('single_signal');
		expect(attributionConfidence('third_party', 'example', true)).toBe('corroborated');
		expect(attributionConfidence('third_party', 'abc', false)).toBe('uncorroborated');
		expect(attributionConfidence('owned_by_seed', 'abc', false)).toBe('corroborated');
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

async function runFor(candidate: Zone) {
	installMock({ [SEED]: SEED_ZONE, 'example.com': candidate });
	const { checkLookalikes } = await import('../src/tools/check-lookalikes');
	const result = await checkLookalikes(SEED);
	const own = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'example.com');
	return {
		own,
		attribution: own.find((f) => f.metadata?.findingAxis === 'attribution'),
		threat: own.find((f) => f.metadata?.findingAxis === 'threat_observation'),
	};
}

describe('checkLookalikes — agency-hosted defensive cohort (#974)', () => {
	it('a TLD variant on agency NS with the seed A + MX is not reported third_party, and is not advised for takedown', async () => {
		const { own, attribution, threat } = await runFor({ NS: AGENCY_NS.map((h) => `${h}.`), A: SEED_A, MX: mxRecords(SEED_MX) });
		expect(own.length).toBeGreaterThan(0);
		expect(own.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(false);
		expect(own.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(attribution).toBeDefined();
		expect(attribution!.metadata?.ownershipVerdict).toBe('unattributed');
		expect(attribution!.severity).toBe('info');
		expect(attribution!.detail).not.toContain('registered to a different organisation');
		// The observation is copyable-record-based, so it stays — only the advice changes.
		expect(threat).toBeDefined();
		expect(threat!.detail).toContain('Do NOT block it at the gateway');
		expect(threat!.detail).not.toContain('does not appear to belong to the scanned organisation');
	});

	it('shared-provider MX only (distinct A) is unchanged: third_party with the takedown advice', async () => {
		const { attribution, threat } = await runFor({ NS: AGENCY_NS.map((h) => `${h}.`), A: ['198.51.100.7'], MX: mxRecords(SEED_MX) });
		expect(attribution!.metadata?.ownershipVerdict).toBe('third_party');
		expect(threat!.detail).toContain('block or quarantine mail bearing that name at the gateway');
	});

	it('a one-signal third_party (distinct NS, A and MX) reports single_signal, not corroborated', async () => {
		const { attribution } = await runFor({ NS: AGENCY_NS.map((h) => `${h}.`), A: ['198.51.100.7'], MX: ['10 mail.attacker.example.'] });
		expect(attribution!.metadata?.ownershipVerdict).toBe('third_party');
		expect(attribution!.metadata?.attributionConfidence).toBe('single_signal');
	});
});
