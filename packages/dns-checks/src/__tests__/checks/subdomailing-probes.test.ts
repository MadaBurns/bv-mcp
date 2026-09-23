// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit coverage for the SubdoMailing probe primitives: `probeIncludeDomain` (per-domain
 * takeover-risk classification) and `probeAllIncludes` (fan-out + finding assembly).
 *
 * `extractSpfIncludeChain` / the SPF-walk materialization is out of scope here — this file
 * only drives the two probe functions directly with a mocked `DNSQueryFunction`.
 *
 * Two source-behavior notes surfaced while writing these tests (not fixed — TEST-ONLY scope,
 * see #1094c):
 *
 * 1. `probeAllIncludes` does not itself enforce `MAX_INCLUDE_PROBES` — the 15-domain cap is
 *    applied upstream, in `replayIncludeWalk`, before the `Map` it receives is built. Handing
 *    `probeAllIncludes` 16 entries directly probes all 16. See the skipped test below for a
 *    repro.
 * 2. `SubdomailingRiskType` includes `'expired_domain'` and `titleForRisk` has a case for it,
 *    but nothing in `probeIncludeDomain` ever returns that riskType (confirmed by grep — the
 *    string appears only in the type union and the switch). It cannot be exercised through the
 *    public API with any DNS shape. See the skipped test below.
 */

import { describe, it, expect, vi } from 'vitest';
import { MAX_INCLUDE_PROBES, probeAllIncludes, probeIncludeDomain } from '../../checks/subdomailing-analysis';
import type { DNSQueryFunction } from '../../types';

type DnsRule = string[] | Error;
type RecordedCall = { domain: string; recordType: string };

/**
 * Build a `DNSQueryFunction` from a `"domain:RECORDTYPE"` → rule map. A missing key resolves
 * to `[]` (a real, answered-empty lookup — the DNS analogue of NOERROR/NXDOMAIN at this
 * projection's granularity). An `Error` rule rejects, modeling a resolver failure/timeout that
 * never produced an answer.
 */
function createMockDNS(rules: Record<string, DnsRule>, calls?: RecordedCall[]): DNSQueryFunction {
	return vi.fn(async (domain: string, recordType: string) => {
		calls?.push({ domain, recordType });
		const rule = rules[`${domain}:${recordType}`];
		if (rule === undefined) return [];
		if (rule instanceof Error) throw rule;
		return rule;
	});
}

describe('probeIncludeDomain', () => {
	it('flags a CNAME to a known takeover service that does not resolve as dangling_cname', async () => {
		const queryDNS = createMockDNS({
			'evil.example.com:CNAME': ['abandoned.herokuapp.com.'],
			'abandoned.herokuapp.com:A': [],
		});
		const result = await probeIncludeDomain('evil.example.com', 'include:evil.example.com', queryDNS);
		expect(result.riskType).toBe('dangling_cname');
		expect(result.severity).toBe('critical');
		expect(result.cnameTarget).toBe('abandoned.herokuapp.com');
		expect(result.takeoverService).toBe('abandoned.herokuapp.com');
		expect(result.detail).toContain('evil.example.com');
		expect(result.detail).toContain('abandoned.herokuapp.com');
	});

	it('does not flag a CNAME to a takeover-pattern host that still resolves', async () => {
		const queryDNS = createMockDNS({
			'shop.example.com:CNAME': ['storefront.myshopify.com.'],
			'storefront.myshopify.com:A': ['203.0.113.5'],
			'shop.example.com:NS': [],
			'shop.example.com:TXT': ['v=spf1 -all'],
		});
		const result = await probeIncludeDomain('shop.example.com', 'include:shop.example.com', queryDNS);
		expect(result.riskType).toBeNull();
	});

	it('ignores a CNAME that does not match a recognized takeover-service pattern', async () => {
		const queryDNS = createMockDNS({
			'own.example.com:CNAME': ['internal-host.own.example.com.'],
			'own.example.com:NS': [],
			'own.example.com:TXT': ['v=spf1 -all'],
		});
		const result = await probeIncludeDomain('own.example.com', 'include:own.example.com', queryDNS);
		expect(result.riskType).toBeNull();
	});

	it('flags an SPF include whose nameservers do not resolve as dangling_ns', async () => {
		const queryDNS = createMockDNS({
			'lame.example.com:CNAME': [],
			'lame.example.com:NS': ['ns1.lame-provider.com.', 'ns2.lame-provider.com.'],
			'ns1.lame-provider.com:A': [],
			'ns2.lame-provider.com:A': [],
		});
		const result = await probeIncludeDomain('lame.example.com', 'include:lame.example.com', queryDNS);
		expect(result.riskType).toBe('dangling_ns');
		expect(result.severity).toBe('high');
		expect(result.nsTargets).toEqual(['ns1.lame-provider.com', 'ns2.lame-provider.com']);
		expect(result.detail).toContain('ns1.lame-provider.com');
	});

	it('treats a nameserver A-lookup that throws the same as one that resolves empty (dangling)', async () => {
		const queryDNS = createMockDNS({
			'throws-ns.example.com:CNAME': [],
			'throws-ns.example.com:NS': ['ns1.throws.com.'],
			'ns1.throws.com:A': new Error('SERVFAIL'),
		});
		const result = await probeIncludeDomain('throws-ns.example.com', 'include:throws-ns.example.com', queryDNS);
		expect(result.riskType).toBe('dangling_ns');
		expect(result.nsTargets).toEqual(['ns1.throws.com']);
	});

	it('flags dangling_ns even when only some of several nameservers fail to resolve', async () => {
		const queryDNS = createMockDNS({
			'mixed.example.com:CNAME': [],
			'mixed.example.com:NS': ['ns1.ok.com.', 'ns2.bad.com.'],
			'ns1.ok.com:A': ['1.2.3.4'],
			'ns2.bad.com:A': [],
		});
		const result = await probeIncludeDomain('mixed.example.com', 'include:mixed.example.com', queryDNS);
		expect(result.riskType).toBe('dangling_ns');
		expect(result.nsTargets).toEqual(['ns2.bad.com']);
	});

	it('flags an include with no SPF record as void_include', async () => {
		const queryDNS = createMockDNS({
			'quiet.example.com:CNAME': [],
			'quiet.example.com:NS': [],
			'quiet.example.com:TXT': ['unrelated txt record'],
		});
		const result = await probeIncludeDomain('quiet.example.com', 'include:quiet.example.com', queryDNS);
		expect(result.riskType).toBe('void_include');
		expect(result.severity).toBe('low');
		expect(result.detail).toContain('has no SPF record');
	});

	it('reports no risk for a healthy include with a valid SPF record', async () => {
		const queryDNS = createMockDNS({
			'healthy.example.com:CNAME': [],
			'healthy.example.com:NS': ['ns1.good-provider.com.'],
			'ns1.good-provider.com:A': ['1.2.3.4'],
			'healthy.example.com:TXT': ['v=spf1 -all'],
		});
		const result = await probeIncludeDomain('healthy.example.com', 'include:healthy.example.com', queryDNS);
		expect(result.riskType).toBeNull();
		expect(result.severity).toBe('info');
		expect(result.detail).toContain('no takeover risk detected');
	});

	it.skip(
		"exercises 'expired_domain' via probeIncludeDomain — no DNS shape can produce it: the riskType exists in the type union and in titleForRisk's switch, but nothing in probeIncludeDomain's CNAME/NS/TXT sequence ever returns it (grep-confirmed, see file header note). Unreachable through the public API.",
		() => {},
	);

	describe('a probe that never reached the origin is not recorded the same way as a real answered-empty result', () => {
		it('an answered-empty TXT lookup (real NOERROR/NXDOMAIN-shaped negative) is worded as a measured absence', async () => {
			const queryDNS = createMockDNS({
				'answered.example.com:CNAME': [],
				'answered.example.com:NS': [],
				'answered.example.com:TXT': [],
			});
			const result = await probeIncludeDomain('answered.example.com', 'include:answered.example.com', queryDNS);
			expect(result.riskType).toBe('void_include');
			expect(result.detail).toContain('has no SPF record');
		});

		it('a resolver error on the TXT probe is worded as "could not be queried", not "has no SPF record"', async () => {
			const queryDNS = createMockDNS({
				'errored.example.com:CNAME': [],
				'errored.example.com:NS': [],
				'errored.example.com:TXT': new Error('SERVFAIL'),
			});
			const result = await probeIncludeDomain('errored.example.com', 'include:errored.example.com', queryDNS);
			expect(result.riskType).toBe('void_include');
			expect(result.detail).toContain('could not be queried');
			expect(result.detail).not.toContain('has no SPF record');
		});

		it('a timeout on the TXT probe gets the same "could not be queried" wording as any other resolver error', async () => {
			const queryDNS = createMockDNS({
				'timedout.example.com:CNAME': [],
				'timedout.example.com:NS': [],
				'timedout.example.com:TXT': new Error('DNS query timed out after 3000ms'),
			});
			const result = await probeIncludeDomain('timedout.example.com', 'include:timedout.example.com', queryDNS);
			expect(result.riskType).toBe('void_include');
			expect(result.detail).toContain('could not be queried');
		});

		// NOTE (not fixed — TEST-ONLY scope): the two tests above show `probeIncludeDomain`
		// gives a resolver error and a real answered-empty TXT the SAME `riskType` ('void_include')
		// and the SAME `severity` ('low') — they differ only in `detail` wording. A caller that
		// reads riskType/severity alone (as `probeAllIncludes` does when building findings) cannot
		// tell "the origin was never reached" from "we measured and it's genuinely absent". This
		// is the shape CLAUDE.md's missingControl-vs-inconclusive rule warns about; flagged for
		// the orchestrator, not fixed here.
	});
});

describe('probeAllIncludes', () => {
	it('MAX_INCLUDE_PROBES is pinned at 15', () => {
		expect(MAX_INCLUDE_PROBES).toBe(15);
	});

	it.skip(
		'does NOT itself cap probes at MAX_INCLUDE_PROBES — the 15-domain cap is enforced upstream in replayIncludeWalk/extractSpfIncludeChain before the map is built, not inside probeAllIncludes. Repro: pass a 16-entry Map directly and count distinct probed domains — it probes all 16, not 15.',
		async () => {
			const calls: RecordedCall[] = [];
			const includes = new Map<string, string>();
			for (let i = 0; i < 16; i++) includes.set(`inc${i}.example.com`, `include:inc${i}.example.com`);
			const queryDNS = createMockDNS({}, calls);
			await probeAllIncludes(includes, queryDNS);
			const probedDomains = new Set(calls.map((c) => c.domain));
			expect(probedDomains.size).toBe(15);
		},
	);

	it('de-duplicates because the input Map cannot hold two entries for the same domain key', async () => {
		const calls: RecordedCall[] = [];
		const includes = new Map<string, string>();
		includes.set('dup.example.com', 'include:dup.example.com (first)');
		includes.set('dup.example.com', 'include:dup.example.com (second)'); // overwrites — Map key semantics
		expect(includes.size).toBe(1);
		const queryDNS = createMockDNS(
			{
				'dup.example.com:CNAME': [],
				'dup.example.com:NS': [],
				'dup.example.com:TXT': ['v=spf1 -all'],
			},
			calls,
		);
		await probeAllIncludes(includes, queryDNS);
		const cnameCalls = calls.filter((c) => c.domain === 'dup.example.com' && c.recordType === 'CNAME');
		expect(cnameCalls).toHaveLength(1);
	});

	it('a domain whose every DNS query rejects still yields findings for the other domains in the batch', async () => {
		const includes = new Map<string, string>([
			['healthy.example.com', 'include:healthy.example.com'],
			['hostile.example.com', 'include:hostile.example.com'],
		]);
		const queryDNS = createMockDNS({
			'healthy.example.com:CNAME': [],
			'healthy.example.com:NS': [],
			'healthy.example.com:TXT': ['v=spf1 -all'],
			'hostile.example.com:CNAME': new Error('boom'),
			'hostile.example.com:NS': new Error('boom'),
			'hostile.example.com:TXT': new Error('boom'),
		});
		const findings = await probeAllIncludes(includes, queryDNS);
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.includeDomain).toBe('hostile.example.com');
	});

	it('produces the documented title for each reachable risk type', async () => {
		const includes = new Map<string, string>([
			['cname-risk.example.com', 'include:cname-risk.example.com'],
			['ns-risk.example.com', 'include:ns-risk.example.com'],
			['void-risk.example.com', 'include:void-risk.example.com'],
		]);
		const queryDNS = createMockDNS({
			'cname-risk.example.com:CNAME': ['dangling.herokuapp.com.'],
			'dangling.herokuapp.com:A': [],
			'ns-risk.example.com:CNAME': [],
			'ns-risk.example.com:NS': ['ns1.dead.com.'],
			'ns1.dead.com:A': [],
			'void-risk.example.com:CNAME': [],
			'void-risk.example.com:NS': [],
			'void-risk.example.com:TXT': [],
		});
		const findings = await probeAllIncludes(includes, queryDNS);
		const byRisk = new Map(findings.map((f) => [f.metadata?.riskType as string | undefined, f.title]));
		expect(byRisk.get('dangling_cname')).toBe('Dangling CNAME in SPF include chain');
		expect(byRisk.get('dangling_ns')).toBe('Dangling NS delegation in SPF include chain');
		expect(byRisk.get('void_include')).toBe('Void SPF include');
		expect(findings).toHaveLength(3);
	});

	it('gates more includes than PROBE_CONCURRENCY without dropping any probe result', async () => {
		// More domains than the internal concurrency width so at least one probe must queue
		// behind the gate (gateQueries' waiting-list path) rather than firing immediately.
		const calls: RecordedCall[] = [];
		const includes = new Map<string, string>();
		for (let i = 0; i < 6; i++) includes.set(`wide${i}.example.com`, `include:wide${i}.example.com`);
		const rules: Record<string, DnsRule> = {};
		for (let i = 0; i < 6; i++) {
			rules[`wide${i}.example.com:CNAME`] = [];
			rules[`wide${i}.example.com:NS`] = [];
			rules[`wide${i}.example.com:TXT`] = ['v=spf1 -all'];
		}
		const queryDNS = createMockDNS(rules, calls);
		const findings = await probeAllIncludes(includes, queryDNS);
		expect(findings).toHaveLength(0); // all six are healthy
		expect(calls).toHaveLength(18); // CNAME + NS + TXT per domain, none dropped or duplicated
	});

	it('produces no finding for a healthy include (riskType null is filtered out)', async () => {
		const includes = new Map<string, string>([['healthy.example.com', 'include:healthy.example.com']]);
		const queryDNS = createMockDNS({
			'healthy.example.com:CNAME': [],
			'healthy.example.com:NS': [],
			'healthy.example.com:TXT': ['v=spf1 -all'],
		});
		const findings = await probeAllIncludes(includes, queryDNS);
		expect(findings).toHaveLength(0);
	});
});
