// SPDX-License-Identifier: BUSL-1.1

/**
 * Partial lame delegation ("Sitting Ducks") — CRITICAL escalation + claimability gate.
 *
 * WHY THIS FILE EXISTS.
 * Escalating the partial-lame finding from `high` to `critical` moves NO score on its
 * own: the engine's critical penalty counts only findings that are BOTH `critical` AND
 * `verified` (`scoring/engine.ts` — `verifiedCriticalCount`), and `verified` comes only
 * from an explicit `metadata.confidence`. So the escalation is really TWO changes, and
 * the second one is an ATTESTATION: stamping `verified` says the package proved this.
 *
 * What must it have proved? Not lameness — lameness alone is a reachability defect. The
 * published prose claims a HIJACK PRECONDITION ("an attacker who registers the unclaimed
 * nameserver becomes authoritative"), and that is only true when the dead nameserver is
 * actually CLAIMABLE. A SERVFAIL-only or address-less nameserver whose base domain is
 * registered is lame but NOT shown hijackable, and stamping it `verified` would publish
 * an over-claim on a customer-visible surface.
 *
 * Hence the split these tests lock: `verified` ⟺ claimable-shown; everything else keeps
 * `deterministic` and therefore moves no score.
 */

import { describe, expect, it } from 'vitest';
import { checkNS } from '../../checks/check-ns';
import {
	CONFIDENCE_DEMOTING_PHRASES,
	assessLameDelegation,
	getPartialLameDelegationFinding,
	getTotalLameDelegationFinding,
} from '../../checks/ns-analysis';
import { inferFindingConfidence } from '../../check-utils';
import { scoreIndicatesMissingControl } from '../../scoring';
import type { Finding, RawDNSResponse } from '../../types';

const RCODE_NOERROR = 0;
const RCODE_SERVFAIL = 2;
const RCODE_NXDOMAIN = 3;

const A_ANSWER = { type: 1, data: '192.0.2.1' };
const NS_ANSWER = { type: 2, data: 'ns1.registrar.example.' };

/**
 * Build a `checkNS` resolver pair over a declarative table.
 *
 * `raw[name][type]` supplies the DoH response for that exact (name, type). Anything
 * unlisted answers NOERROR/empty, which is the honest default for "the name exists but
 * has no such record" — the case that must NOT read as claimable.
 */
function resolvers(
	nsRecords: string[],
	raw: Record<string, Partial<Record<string, RawDNSResponse>>>,
): { queryDNS: never; rawQueryDNS: never; queries: string[] } {
	const queries: string[] = [];
	const queryDNS = (async (name: string, type: string) => {
		queries.push(`${type} ${name}`);
		if (type === 'NS' && name === 'victim.example') return nsRecords;
		return [];
	}) as never;
	const rawQueryDNS = (async (name: string, type: string): Promise<RawDNSResponse> => {
		queries.push(`${type} ${name}`);
		return raw[name]?.[type] ?? { Status: RCODE_NOERROR, Answer: [] };
	}) as never;
	return { queryDNS, rawQueryDNS, queries };
}

function lameFinding(findings: Finding[]): Finding | undefined {
	return findings.find((f) => f.metadata?.lameDelegation === 'partial');
}

// ---------------------------------------------------------------------------
// C0 — claimability discrimination. The ethical core: `verified` must attest what
// was ACTUALLY verified, not merely what the prose asserts.
// ---------------------------------------------------------------------------

describe('claimability gate on the partial lame-delegation finding', () => {
	it('stamps verified confidence only when the dead NS is shown claimable', async () => {
		// ns2.abandoned.example has NO address AND its registrable base domain answers
		// NXDOMAIN — the base domain is unregistered, so anyone can register it and become
		// authoritative for victim.example. That IS the Sitting Ducks precondition, and it
		// is the only shape this package can PROVE from a recursive-resolver vantage.
		const { queryDNS, rawQueryDNS } = resolvers(
			['ns1.healthy.example', 'ns2.abandoned.example'],
			{
				'ns1.healthy.example': { A: { Status: RCODE_NOERROR, Answer: [A_ANSWER] } },
				'ns2.abandoned.example': {
					A: { Status: RCODE_NXDOMAIN, Answer: [] },
					AAAA: { Status: RCODE_NXDOMAIN, Answer: [] },
				},
				'abandoned.example': { NS: { Status: RCODE_NXDOMAIN, Answer: [] } },
			},
		);

		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		const f = lameFinding(result.findings);

		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
		expect(f!.metadata?.confidence).toBe('verified');
		expect(f!.metadata?.claimableNameservers).toEqual(['ns2.abandoned.example']);
	});

	it('keeps deterministic confidence for a lame-but-not-shown-claimable nameserver', async () => {
		// ns2.provider.example is address-less because its A/AAAA lookups SERVFAIL. The
		// delegation is lame — but SERVFAIL is a resolver failure, not proof the name is
		// unregistered, and the base domain provider.example is registered. Nothing here
		// shows an attacker could claim it, so nothing may be attested as `verified`.
		const { queryDNS, rawQueryDNS } = resolvers(
			['ns1.healthy.example', 'ns2.provider.example'],
			{
				'ns1.healthy.example': { A: { Status: RCODE_NOERROR, Answer: [A_ANSWER] } },
				'ns2.provider.example': {
					A: { Status: RCODE_SERVFAIL, Answer: [] },
					AAAA: { Status: RCODE_SERVFAIL, Answer: [] },
				},
				'provider.example': { NS: { Status: RCODE_NOERROR, Answer: [NS_ANSWER] } },
			},
		);

		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		const f = lameFinding(result.findings);

		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
		expect(f!.metadata?.confidence).toBe('deterministic');
		expect(f!.metadata?.claimableNameservers).toBeUndefined();
	});

	it('a registered base domain is NOT claimable even when the NS host itself is NXDOMAIN', async () => {
		// The host record is gone but somebody still owns the base domain. An attacker
		// cannot register what is already registered, so this stays unattested.
		const { queryDNS, rawQueryDNS } = resolvers(
			['ns1.healthy.example', 'ns2.provider.example'],
			{
				'ns1.healthy.example': { A: { Status: RCODE_NOERROR, Answer: [A_ANSWER] } },
				'ns2.provider.example': {
					A: { Status: RCODE_NXDOMAIN, Answer: [] },
					AAAA: { Status: RCODE_NXDOMAIN, Answer: [] },
				},
				'provider.example': { NS: { Status: RCODE_NOERROR, Answer: [NS_ANSWER] } },
			},
		);

		const f = lameFinding((await checkNS('victim.example', queryDNS, { rawQueryDNS })).findings);
		expect(f!.metadata?.confidence).toBe('deterministic');
	});

	it('a failed base-domain probe never manufactures a claim', async () => {
		// The claimability probe THREW. A failure to measure is not a measurement — the
		// same invariant `unknown` probe outcomes already carry in the verdict arithmetic.
		const queryDNS = (async (name: string, type: string) =>
			type === 'NS' && name === 'victim.example' ? ['ns1.healthy.example', 'ns2.abandoned.example'] : []) as never;
		const rawQueryDNS = (async (name: string, type: string): Promise<RawDNSResponse> => {
			if (name === 'ns1.healthy.example') return { Status: RCODE_NOERROR, Answer: [A_ANSWER] };
			if (name === 'ns2.abandoned.example') return { Status: RCODE_NXDOMAIN, Answer: [] };
			if (name === 'abandoned.example' && type === 'NS') throw new Error('resolver timeout');
			return { Status: RCODE_NOERROR, Answer: [] };
		}) as never;

		const f = lameFinding((await checkNS('victim.example', queryDNS, { rawQueryDNS })).findings);
		expect(f!.metadata?.confidence).toBe('deterministic');
	});

	it('spends NO claimability query on a healthy delegation', async () => {
		// Query budget: the claimability probe is confined to the `partial` verdict and to
		// NXDOMAIN nameserver hosts. A healthy zone must cost exactly what it cost before.
		const { queryDNS, rawQueryDNS, queries } = resolvers(
			['ns1.healthy.example', 'ns2.healthy.example'],
			{
				'ns1.healthy.example': { A: { Status: RCODE_NOERROR, Answer: [A_ANSWER] } },
				'ns2.healthy.example': { A: { Status: RCODE_NOERROR, Answer: [A_ANSWER] } },
			},
		);

		await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(queries.filter((q) => q === 'NS healthy.example')).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// C3 — confidence is DECLARED, not inferred from prose.
// ---------------------------------------------------------------------------

describe('the escalation is declared, not prose-dependent', () => {
	const claimable = assessLameDelegation([
		{ nameserver: 'ns1.healthy.example', outcome: 'resolves', hostNxdomain: false },
		{ nameserver: 'ns2.abandoned.example', outcome: 'no_address', hostNxdomain: true },
	]);

	it('declares verified on the finding itself', () => {
		const f = getPartialLameDelegationFinding('victim.example', claimable, ['ns2.abandoned.example']);
		expect(f.metadata?.confidence).toBe('verified');
		expect(inferFindingConfidence(f)).toBe('verified');
	});

	it('neither prose variant contains a phrase that inferFindingConfidence demotes on', () => {
		// The guard that stops a future copy edit from silently disarming the escalation.
		// An explicit `metadata.confidence` already WINS over the prose sniff, so this is
		// belt-and-braces for the declared branch — but it is load-bearing for the
		// not-shown-claimable branch, which relies on the sniff returning `deterministic`
		// rather than `heuristic` (a `heuristic` critical is also uncounted, but for the
		// wrong reason, and the reason is what a reviewer reads).
		const variants = [
			getPartialLameDelegationFinding('victim.example', claimable, ['ns2.abandoned.example']),
			getPartialLameDelegationFinding('victim.example', claimable, []),
		];
		for (const f of variants) {
			const text = `${f.title} ${f.detail}`.toLowerCase();
			for (const phrase of CONFIDENCE_DEMOTING_PHRASES) {
				expect(`${phrase}:${text.includes(phrase)}`).toBe(`${phrase}:false`);
			}
		}
	});

	it('the not-shown-claimable variant does not assert hijackability', () => {
		// The over-claim this whole track exists to prevent: the same sentence cannot be
		// published for a nameserver nobody showed was claimable.
		const f = getPartialLameDelegationFinding('victim.example', claimable, []);
		expect(f.detail).not.toContain('becomes authoritative');
		expect(f.metadata?.confidence).toBe('deterministic');
	});

	it('the claimable variant still names both sides of the split', () => {
		const f = getPartialLameDelegationFinding('victim.example', claimable, ['ns2.abandoned.example']);
		expect(f.detail).toContain('ns2.abandoned.example');
		expect(f.detail).toContain('ns1.healthy.example');
	});

	it('the partial finding still does NOT set missingControl', () => {
		// Escalating severity must not turn a penalty into a category-zeroing absence: the
		// domain HAS nameservers, some are dead. `missingControl` would also be the only
		// route to the 64 critical-gap ceiling, which is deliberately NOT part of this change.
		const f = getPartialLameDelegationFinding('victim.example', claimable, ['ns2.abandoned.example']);
		expect(f.metadata?.missingControl).toBeUndefined();
	});

	it('neither prose variant is read as a MISSING CONTROL by the classifier', () => {
		// The metadata check above is not sufficient. `scoreIndicatesMissingControl` reads
		// PROSE — MISSING_CONTROL_REGEX over title+detail — and a `critical`+`deterministic`
		// match zeroes the entire ns category. Raising the severity to `critical` is exactly
		// what arms that regex: at `high` the same wording was already a match waiting to
		// happen. This caught a live defect during implementation (the phrase "rather than a
		// missing name" dropped ns from 60 to 0 — a bigger, wronger score move than the
		// escalation itself, and invisible in the finding's own metadata).
		for (const claim of [['ns2.abandoned.example'], []]) {
			const f = getPartialLameDelegationFinding('victim.example', claimable, claim);
			expect(scoreIndicatesMissingControl([f])).toBe(false);
		}
	});
});

// ---------------------------------------------------------------------------
// C4 — total-lame must stay inconclusive. A domain whose nameservers ALL failed to
// resolve is a measurement failure, not a hijackable domain.
// ---------------------------------------------------------------------------

describe('the escalation does not touch the TOTAL-lame path', () => {
	const total = assessLameDelegation([
		{ nameserver: 'ns1.abandoned.example', outcome: 'no_address', hostNxdomain: true },
		{ nameserver: 'ns2.abandoned.example', outcome: 'no_address', hostNxdomain: true },
	]);

	it('stays low + inconclusive even when every nameserver is NXDOMAIN-claimable', () => {
		const f = getTotalLameDelegationFinding('victim.example', total);
		expect(f.severity).toBe('low');
		expect(f.metadata?.errorKind).toBe('dns_error');
		expect(f.metadata?.inconclusive).toBe(true);
		expect(f.metadata?.confidence).toBeUndefined();
	});

	it('checkNS routes a total-lame zone to the excluded-category shape, not a CRITICAL', async () => {
		const { queryDNS, rawQueryDNS } = resolvers(
			['ns1.abandoned.example', 'ns2.abandoned.example'],
			{
				'ns1.abandoned.example': { A: { Status: RCODE_NXDOMAIN, Answer: [] }, AAAA: { Status: RCODE_NXDOMAIN, Answer: [] } },
				'ns2.abandoned.example': { A: { Status: RCODE_NXDOMAIN, Answer: [] }, AAAA: { Status: RCODE_NXDOMAIN, Answer: [] } },
				'abandoned.example': { NS: { Status: RCODE_NXDOMAIN, Answer: [] } },
			},
		);

		const result = await checkNS('victim.example', queryDNS, { rawQueryDNS });
		expect(result.checkStatus).toBe('error');
		expect(result.findings.map((f) => f.severity)).toEqual(['low']);
		expect(result.findings.some((f) => f.metadata?.confidence === 'verified')).toBe(false);
	});
});
