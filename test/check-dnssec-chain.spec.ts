// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { RecordType } from '../src/lib/dns-types';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a DoH response containing DS records for a zone. */
function dsResponse(zone: string, records: string[]) {
	return createDohResponse(
		[{ name: zone, type: RecordType.DS }],
		records.map((data) => ({ name: zone, type: RecordType.DS, TTL: 300, data })),
	);
}

/** Build a DoH response containing DNSKEY records for a zone. */
function dnskeyResponse(zone: string, records: string[]) {
	return createDohResponse(
		[{ name: zone, type: RecordType.DNSKEY }],
		records.map((data) => ({ name: zone, type: RecordType.DNSKEY, TTL: 300, data })),
	);
}

/** Build an empty DoH response for a given type. */
function emptyDsResponse(zone: string) {
	return createDohResponse([{ name: zone, type: RecordType.DS }], []);
}

function emptyDnskeyResponse(zone: string) {
	return createDohResponse([{ name: zone, type: RecordType.DNSKEY }], []);
}

/** Build an A-record response with AD flag. */
function adResponse(domain: string, ad: boolean) {
	return createDohResponse(
		[{ name: domain, type: RecordType.A }],
		[{ name: domain, type: RecordType.A, TTL: 300, data: '93.184.216.34' }],
		{ ad },
	);
}

/**
 * Create a fetch mock that routes by URL query params (name + type).
 * `routeMap` keys are "name:type" (e.g. "com:DS", "example.com:DNSKEY", "example.com:A").
 */
function mockDnsFetch(routeMap: Record<string, Response>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL | Request) => {
		const u = new URL(typeof url === 'string' ? url : url instanceof Request ? url.url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';
		const key = `${name}:${type}`;
		const resp = routeMap[key];
		if (resp) return Promise.resolve(resp);
		// Default: empty response
		return Promise.resolve(createDohResponse([{ name, type: 1 }], []));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkDnssecChain', () => {
	async function run(domain = 'example.com') {
		const { checkDnssecChain } = await import('../src/tools/check-dnssec-chain');
		return checkDnssecChain(domain);
	}

	it('fully signed chain reports chainComplete=true', async () => {
		mockDnsFetch({
			// Root zone — DNSKEY only (no DS for root)
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			// com zone
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com zone
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			// AD flag query
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		// Should have at least an info finding with chain summary
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.metadata?.chainComplete === true);
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.metadata!.adFlag).toBe(true);
		// A fully-verified chain is complete and stays cacheable.
		expect(result.partial).toBeFalsy();
	});

	it('Cloudflare mnemonic-format algorithm fields complete the chain', async () => {
		// Cloudflare DoH (prod's primary resolver) returns DNSSEC algorithm fields as
		// IANA MNEMONICS (e.g. "ECDSAP256SHA256"), not numbers. DNSKEY data puts the
		// algorithm at index 2 and DS data at index 1. A numeric-only parser drops
		// every record → the walk falsely reports "stopped at com — not signed".
		mockDnsFetch({
			// Root zone — DNSKEY only, mnemonic algorithm (no DS for root)
			'.:DNSKEY': dnskeyResponse('.', ['257 3 RSASHA256 AwEAAroot...']),
			// com zone — DS + DNSKEY both mnemonic ECDSAP256SHA256 (alg 13)
			'com:DS': dsResponse('com', ['19718 ECDSAP256SHA256 2 ABCDEF0123456789']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 ECDSAP256SHA256 AwEAAcom...']),
			// example.com zone — DS + DNSKEY mnemonic ECDSAP256SHA256
			'example.com:DS': dsResponse('example.com', ['54321 ECDSAP256SHA256 2 FEDCBA9876543210']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['256 3 ECDSAP256SHA256 AwEAAexample...']),
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		// Chain must COMPLETE — not falsely report "stopped at com / not signed".
		const summary = result.findings.find((f) => f.severity === 'info' && f.metadata?.chainComplete !== undefined);
		expect(summary).toBeDefined();
		expect(summary!.metadata!.chainComplete).toBe(true);
		expect(summary!.detail).not.toMatch(/stopped at com/i);
		expect(summary!.detail).not.toMatch(/not signed|unsigned/i);

		// Target zone linkage must be 'linked' (DS ↔ DNSKEY algorithm match on mnemonics).
		const zones = summary!.metadata!.zones as Array<{ zone: string; linkage: string }>;
		const target = zones.find((z) => z.zone === 'example.com');
		expect(target).toBeDefined();
		expect(target!.linkage).toBe('linked');
	});

	it('unsigned domain reports no DS', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com has no DS and no DNSKEY → unsigned
			'example.com:DS': emptyDsResponse('example.com'),
			'example.com:DNSKEY': emptyDnskeyResponse('example.com'),
			'example.com:A': adResponse('example.com', false),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		// Chain stops at unsigned zone — detail should mention "no DS" or "unsigned"
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toMatch(/no DS|unsigned|not signed/i);
	});

	it('unsigned domain scores 60 with a real high finding (#810) — not an accidental 100 pass', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com has no DS and no DNSKEY → unsigned
			'example.com:DS': emptyDsResponse('example.com'),
			'example.com:DNSKEY': emptyDnskeyResponse('example.com'),
			'example.com:A': adResponse('example.com', false),
		});

		const result = await run();

		// Mirrors check_dnssec's "DNSSEC not enabled" finding
		// (packages/dns-checks/src/checks/check-dnssec.ts:143-151): a `high`-labelled
		// finding whose penalty is decoupled to -40 via `penaltyOverride`, so the
		// category lands at 60 rather than an accidental 100 (#810) or a zeroed 0.
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.metadata?.penaltyOverride).toBe(40);

		// Must NOT be flagged as a missing control — that would force the returned
		// score to 0 (buildCheckResult: `score: hasMissingControl ? 0 : score`)
		// instead of the intended 60, per the CLAUDE.md scoring trap for this exact
		// finding class ("missingControl = we MEASURED and the control is absent").
		expect(highFinding!.metadata?.missingControl).toBeUndefined();

		// Aligned with scan_domain's dnssec category for the same unsigned-domain
		// shape (packages/dns-checks/src/__tests__/checks/check-dnssec.test.ts:29-32):
		// score 60, and — since 60 >= 50 and no finding sets missingControl — `passed`
		// is true under this repo's documented `passed = score>=50 && !hasMissingControl`
		// formula ("did not penalize", NOT "control exists"; see CLAUDE.md's `passed`-as-
		// verdict trap). Forcing `passed: false` here would require missingControl,
		// which would also zero the score to 0 — contradicting the 60 this fix targets.
		expect(result.score).toBe(60);
		expect(result.passed).toBe(true);
	});

	it('unsigned ANCESTOR zone (walk stops before target) scores 60, not an accidental 100 pass', async () => {
		// www.example.com where example.com is unsigned (com signed): the walk breaks
		// at example.com before ever reaching the target, so the #820 guard
		// (`reachedTarget && !targetSigned`) never fired and the tool returned
		// score 100 / passed true while check_dnssec scored the same domain 60.
		// The chain of trust is broken at the unsigned ancestor — even a DNSKEY
		// published below it would be an unreachable island of trust.
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com (ANCESTOR of the target) has no DS and no DNSKEY → unsigned
			'example.com:DS': emptyDsResponse('example.com'),
			'example.com:DNSKEY': emptyDnskeyResponse('example.com'),
			'www.example.com:A': adResponse('www.example.com', false),
		});

		const result = await run('www.example.com');

		// Same finding shape as the reached-target case (#820): high severity with a
		// decoupled -40 penalty, and NO missingControl (which would zero the score).
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.metadata?.penaltyOverride).toBe(40);
		expect(highFinding!.metadata?.missingControl).toBeUndefined();

		// The finding is keyed to the zone where the chain terminated unsigned.
		expect(highFinding!.metadata?.zone).toBe('example.com');
		expect(highFinding!.detail).toContain('example.com');

		// Aligned with check_dnssec's 60 for the same shape; passed=true under the
		// documented `passed = score>=50 && !hasMissingControl` formula.
		expect(result.score).toBe(60);
		expect(result.passed).toBe(true);

		// Summary must not claim a complete chain.
		const summary = result.findings.find((f) => f.severity === 'info' && f.metadata?.chainComplete !== undefined);
		expect(summary).toBeDefined();
		expect(summary!.metadata!.chainComplete).toBe(false);
	});

	it('island-of-trust target (DNSKEY published, DS absent at parent) is not chainComplete and scores 60 (#834)', async () => {
		// example.com publishes a DNSKEY but its parent (com) holds no DS for it: the
		// chain of trust from the root anchor terminates at com, the target's DNSKEY
		// is unreachable, and validating resolvers treat the zone as insecure. Before
		// the fix: `targetSigned` accepted the DNSKEY alone, linkage 'no_ds' set
		// neither chainBroken nor the walk break, and the tool reported
		// chainComplete: true / score 100 with no high finding.
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com: DS empty at the parent, DNSKEY populated → island of trust
			'example.com:DS': emptyDsResponse('example.com'),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			'example.com:A': adResponse('example.com', false),
		});

		const result = await run();

		// The summary must NOT claim a complete chain — there is no DS linking the
		// parent to the target's DNSKEY.
		const summary = result.findings.find((f) => f.severity === 'info' && f.metadata?.chainComplete !== undefined);
		expect(summary).toBeDefined();
		expect(summary!.metadata!.chainComplete).toBe(false);

		// Same finding convention as #810/#820: high severity, decoupled -40 penalty
		// (category → 60), and NO missingControl — a published-but-unanchored DNSKEY
		// is MEASURED DNSSEC material, not an absent control; missingControl would
		// zero the score via buildCheckResult's `score: hasMissingControl ? 0 : score`.
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.metadata?.penaltyOverride).toBe(40);
		expect(highFinding!.metadata?.missingControl).toBeUndefined();
		expect(highFinding!.metadata?.zone).toBe('example.com');

		// The wording states the mechanism: DNSKEY published, DS absent at the parent,
		// validating resolvers treat the zone as insecure.
		expect(`${highFinding!.title} ${highFinding!.detail}`).toMatch(/island of trust/i);
		expect(highFinding!.detail).toMatch(/DNSKEY/);
		expect(highFinding!.detail).toMatch(/DS/);
		expect(highFinding!.detail).toMatch(/insecure/i);

		// Score 60 / passed true, per the documented `passed = score>=50 && !hasMissingControl`
		// formula ("did not penalize", NOT "control exists").
		expect(result.score).toBe(60);
		expect(result.passed).toBe(true);
	});

	it('broken linkage (DS exists but no DNSKEY) produces high severity', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com has DS but NO DNSKEY → broken
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': emptyDnskeyResponse('example.com'),
			'example.com:A': adResponse('example.com', false),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.detail).toMatch(/broken|no DNSKEY|mismatch/i);
	});

	it('empty root DNSKEY (trust-anchor retrieval failure) does NOT report a broken chain', async () => {
		// The root is a global trust anchor and is ALWAYS signed. An empty DNSKEY
		// result for "." can only mean the query failed/was-served-empty (e.g. the
		// prod edge-cache emptiness) — never that the chain is broken. The rest of
		// the chain (com, example.com) is fully signed here.
		mockDnsFetch({
			'.:DNSKEY': emptyDnskeyResponse('.'),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();

		// No false HIGH "broken chain at ." finding.
		const brokenHigh = result.findings.find((f) => f.severity === 'high' && /broken/i.test(f.title));
		expect(brokenHigh).toBeUndefined();

		// Root unverifiability is surfaced as a non-high note — NOT the (root-inaccurate)
		// "DS record exists but no DNSKEY found" message.
		const rootNote = result.findings.find(
			(f) => /root/i.test(f.title) && /unverif|could not|trust anchor/i.test(`${f.title} ${f.detail ?? ''}`),
		);
		expect(rootNote).toBeDefined();
		expect(rootNote!.severity).not.toBe('high');
		expect(rootNote!.detail).not.toMatch(/DS record exists but no DNSKEY/i);

		// An unverified-root result is incomplete (transient retrieval failure) and
		// must NOT be cached — marking it partial makes the dispatch cache predicate
		// skip it, so a one-off empty can't persist and be served stale (#199).
		expect(result.partial).toBe(true);
	});

	it('maps algorithm 8 to RSA-SHA256', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();

		// At least one zone should have RSA-SHA256 in its metadata
		const chainFinding = result.findings.find((f) => f.severity === 'info' && f.metadata?.zones);
		expect(chainFinding).toBeDefined();
		const zones = chainFinding!.metadata!.zones as Array<{ algorithms?: string[] }>;
		const allAlgs = zones.flatMap((z) => z.algorithms ?? []);
		expect(allAlgs).toContain('RSA-SHA256');
	});

	it('weak algorithm (algo 5 → RSA-SHA1) produces medium severity', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 5 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 5 1 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 5 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 5 1 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 5 AwEAAexample...']),
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.detail).toMatch(/weak|RSA-SHA1|deprecated/i);
	});

	it('deep subdomain walks root→com→example.com→sub.example.com', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			'sub.example.com:DS': dsResponse('sub.example.com', ['11111 8 2 11223344']),
			'sub.example.com:DNSKEY': dnskeyResponse('sub.example.com', ['257 3 8 AwEAAsub...']),
			'sub.example.com:A': adResponse('sub.example.com', true),
		});

		const result = await run('sub.example.com');
		expect(result.category).toBe('dnssec_chain');

		const chainFinding = result.findings.find((f) => f.severity === 'info' && f.metadata?.zones);
		expect(chainFinding).toBeDefined();
		const zones = chainFinding!.metadata!.zones as Array<{ zone: string }>;
		const zoneNames = zones.map((z) => z.zone);
		expect(zoneNames).toContain('.');
		expect(zoneNames).toContain('com');
		expect(zoneNames).toContain('example.com');
		expect(zoneNames).toContain('sub.example.com');
	});
});
