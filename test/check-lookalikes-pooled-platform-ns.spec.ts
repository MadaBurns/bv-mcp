// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-36 — the POOLED half of the #929 shared-platform rule.
 *
 * #929 established that an IDENTICAL nameserver set on a UNIFORM platform
 * (one.com's `ns01`/`ns02`) observes nothing about ownership, because that
 * platform hands every tenant the same set. The MIRROR, measured live on
 * 2026-09-17, is that a NON-identical set on a POOLED platform observes nothing
 * about DISTINCTNESS either:
 *
 *   anz.com    NS  a1-206, a16-67, a28-67, a7-66, a8-67, a9-67 .akam.net
 *   anz.co.nz  NS  a1-6, a12-66, a28-67, a3-66, a6-65, a9-65 .akam.net
 *                  + ns1.anz.co.nz, ns2.anz.co.nz
 *
 * Akamai draws six hostnames per ZONE from a pool of ~128, so two zones held by
 * ONE account are assigned different sets by design — the 1-of-6 coincidence is
 * the same class of accident as the repo's own measurement that the UNRELATED
 * bnz.co.nz shares a9-65.akam.net with anz.co.nz (`SHARED_NS_APEXES`, Akamai
 * entry). Before this arm, `classifyOwnership()` read "different hostnames" as
 * distinct infrastructure and reported the bank's own NZ domain as `third_party`
 * — rendered "is registered to a different organisation" by the gate template.
 *
 * WHAT THIS ARM MAY NOT DO, and is pinned here not to do:
 *  - it never returns `owned_by_seed` (Ruling A: no candidate-published record
 *    may earn ownership), so it never lifts the `info` attribution ceiling and
 *    never suppresses the separate threat observation;
 *  - a self-referential nameserver (`ns1.<candidate>`) is counted as NEITHER
 *    ownership evidence NOR distinctness evidence — anyone holding the zone can
 *    publish one, so it names no operator;
 *  - a candidate carrying ANY host that is neither on the seed's pooled platform
 *    nor self-referential (`ns1.attacker.example`) stays out of the arm;
 *  - only an EXACT-LABEL TLD variant reaches it at all, so #929's pinned
 *    bnz.co.nz / anz.co.nz outcome (a character edit — the squatter's shape —
 *    between two unrelated banks who both use Akamai) is untouched.
 */

import { describe, it, expect } from 'vitest';
import { isSharedNsHost, isPooledSharedNsHost } from '../src/tenants/discovery/shared-ns-hosts';
import type { RegistrationState } from '../src/lib/registration-state';

// ---------------------------------------------------------------------------
// Live-transcribed records (DoH / dig @1.1.1.1, 2026-09-17)
// ---------------------------------------------------------------------------

const ANZ_COM_NS = ['a1-206.akam.net', 'a16-67.akam.net', 'a28-67.akam.net', 'a7-66.akam.net', 'a8-67.akam.net', 'a9-67.akam.net'];
const ANZ_CO_NZ_AKAMAI_NS = ['a1-6.akam.net', 'a12-66.akam.net', 'a28-67.akam.net', 'a3-66.akam.net', 'a6-65.akam.net', 'a9-65.akam.net'];
const ANZ_CO_NZ_VANITY_NS = ['ns1.anz.co.nz', 'ns2.anz.co.nz'];
const ANZ_CO_NZ_NS = [...ANZ_CO_NZ_AKAMAI_NS, ...ANZ_CO_NZ_VANITY_NS];
/** An UNRELATED bank, wholly on Akamai, sharing ZERO hosts with anz.com. */
const BNZ_CO_NZ_NS = ['a1-97.akam.net', 'a16-65.akam.net', 'a24-64.akam.net', 'a3-67.akam.net', 'a8-66.akam.net', 'a9-65.akam.net'];
const ONE_COM_NS = ['ns01.one.com', 'ns02.one.com'];

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

async function loadAttribution() {
	return import('../src/lib/ownership-attribution');
}

// ---------------------------------------------------------------------------

describe('classifyOwnership — a pooled provider assigning different hostnames is not distinct infrastructure (SQ-36)', () => {
	it('the live anz.com / anz.co.nz pair is unattributed with ns_shared_platform, not third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'anz.co.nz',
			registration: registered(ANZ_CO_NZ_NS),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.strength).toBe('none');
		expect(result.signals).toEqual(['ns_shared_platform']);
		// The two sentences the old outcome produced, both false here.
		expect(result.rationale).not.toContain('no ownership signal links it');
		expect(result.rationale).not.toContain('remaining nameservers are distinct');
		// What was actually observed is named, so a reader can audit it.
		expect(result.rationale).toContain('akam.net');
		expect(result.rationale).toContain('ns1.anz.co.nz');
	});

	it('the arm never lifts the severity ceiling — the verdict is still capped at info', async () => {
		const { classifyOwnership, capAttributionSeverity } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'anz.co.nz',
			registration: registered(ANZ_CO_NZ_NS),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).not.toBe('owned_by_seed');
		expect(capAttributionSeverity(result.verdict)).toBe('info');
	});

	it('an UNRELATED bank on the same pooled provider is NOT covered — a character-edit label stays third_party', async () => {
		// bnz.co.nz is a different bank that also sits wholly on Akamai (and the
		// repo's own measurement has it sharing a9-65.akam.net with anz.co.nz).
		// A character edit is the squatter's shape, so the exact-label bar keeps
		// this pair — and #929's pinned outcome for it — out of the arm.
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'bnz.co.nz',
			registration: registered(BNZ_CO_NZ_NS),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
	});

	it("declines for the squatter's shape: the seed's platform PLUS a host of its own", async () => {
		// Exact label, so only the attacker-owned nameserver rejects this one.
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'anz.xyz',
			registration: registered([...ANZ_CO_NZ_AKAMAI_NS, 'ns1.attacker.example']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.verdict).not.toBe('owned_by_seed');
	});

	it('declines when the candidate is only self-referential — a vanity nameserver alone attributes nothing', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'anz.xyz',
			registration: registered(['ns1.anz.xyz', 'ns2.anz.xyz']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.signals).toEqual(['distinct_infrastructure']);
	});

	it('declines when the SEED is not wholly on the pooled provider', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: [...ANZ_COM_NS, 'ns1.anz.com.example'],
			candidateDomain: 'anz.co.nz',
			registration: registered(ANZ_CO_NZ_NS),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('declines on a NON-pooled shared platform — the #929 one.com squatter shape is unchanged', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'net-agents.dk',
			seedNs: ONE_COM_NS,
			candidateDomain: 'net-agent.dk',
			registration: registered([...ONE_COM_NS, 'ns1.attacker.example']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.rationale).toContain('remaining nameservers are distinct');
	});

	it('the pooled predicate still defaults CLOSED — without it the arm cannot fire', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'anz.co.nz',
			registration: registered(ANZ_CO_NZ_NS),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
	});
});

describe('buildOwnershipGateMetadata — a NON-owned finding publishes its signals too (SQ-36)', () => {
	// Deliberately driven by an ORDINARY third-party candidate, not by the pooled
	// arm above: this pins the metadata surface on its own, so a revert of either
	// change fails its own assertion rather than both failing on one verdict.
	it('carries ownershipStrength and ownershipSignals alongside the verdict', async () => {
		const { classifyOwnership, buildNonOwnedGateFinding } = await loadAttribution();
		const ownership = classifyOwnership({
			seedDomain: 'anz.com',
			seedNs: ANZ_COM_NS,
			candidateDomain: 'anz-login.com',
			registration: registered(['ns1.attacker.example', 'ns2.attacker.example']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(ownership.verdict).toBe('third_party');
		const gated = buildNonOwnedGateFinding(
			{
				category: 'lookalikes' as const,
				title: 'raw',
				severity: 'medium' as const,
				detail: 'raw detail',
				metadata: { lookalikeDomain: 'anz-login.com' },
			},
			ownership,
			'anz',
			false,
			'info',
			{ category: 'lookalikes', domainMetadataKey: 'lookalikeDomain', postureNoun: 'DNS/mail posture' },
		);
		// The defect SQ-36 opened on: the verdict travelled, the evidence for it
		// did not, so an absent signal list was indistinguishable from an
		// unevaluated one.
		expect(gated.metadata?.ownershipVerdict).toBe('third_party');
		expect(gated.metadata?.ownershipStrength).toBe('none');
		expect(gated.metadata?.ownershipSignals).toEqual(['distinct_infrastructure']);
		expect(gated.severity).toBe('info');
	});
});
