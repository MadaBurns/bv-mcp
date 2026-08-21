// Audit test: every MCP tool must have explicit per-tool free-tier quota
// coverage decision — either an entry in FREE_TOOL_DAILY_LIMITS, or explicit
// membership in INTENTIONALLY_UNLIMITED_TOOLS (covered by per-IP only).
//
// Background: prior to v2.10.8, tools omitted from FREE_TOOL_DAILY_LIMITS
// silently fell back to per-IP rate limiting. That was sometimes intended,
// sometimes a bug (e.g. check_dane_https / check_svcb_https shipped without
// quotas because nobody noticed). This audit forces the decision to be
// explicit and visible in code review.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';
import {
	FREE_TOOL_DAILY_LIMITS,
	INTENTIONALLY_UNLIMITED_TOOLS,
	INTERNAL_ONLY_TOOLS,
	INTENTIONALLY_PARTNER_FLAT_TOOLS,
	RATE_LIMIT_ALIAS_KEYS,
	TIER_TOOL_DAILY_LIMITS,
	TIER_DAILY_LIMITS,
} from '../../src/lib/config';

const IDENTITY_SECOPS_TOOLS = ['query_signins', 'query_ual', 'get_ca_policies', 'assess_coverage'] as const;

describe('tool-quota-coverage audit', () => {
	it('every public TOOL_DEFS entry is either quota-limited or explicitly unlimited (never neither, never both)', () => {
		const limited = new Set(Object.keys(FREE_TOOL_DAILY_LIMITS));
		const unlimited = INTENTIONALLY_UNLIMITED_TOOLS;

		const missing: string[] = [];
		const both: string[] = [];

		for (const tool of TOOLS) {
			// Internal-only tools are removed from the public surface (rejected on /mcp),
			// so they carry no public free-tier quota — exempt from the coverage requirement.
			if (INTERNAL_ONLY_TOOLS.has(tool.name)) continue;
			const inLimited = limited.has(tool.name);
			const inUnlimited = unlimited.has(tool.name);
			if (!inLimited && !inUnlimited) missing.push(tool.name);
			if (inLimited && inUnlimited) both.push(tool.name);
		}

		expect(missing, `tools missing from BOTH FREE_TOOL_DAILY_LIMITS and INTENTIONALLY_UNLIMITED_TOOLS: ${missing.join(', ')}`).toEqual([]);
		expect(both, `tools listed in BOTH (must pick one): ${both.join(', ')}`).toEqual([]);
	});

	it('INTENTIONALLY_UNLIMITED_TOOLS membership is a subset of TOOL_DEFS names', () => {
		const validNames = new Set(TOOLS.map((t) => t.name));
		const stale = [...INTENTIONALLY_UNLIMITED_TOOLS].filter((name) => !validNames.has(name));
		expect(stale, `INTENTIONALLY_UNLIMITED_TOOLS contains names not in TOOL_DEFS: ${stale.join(', ')}`).toEqual([]);
	});

	it('identity-secops tools are quota-limited, not in the unlimited exception set', () => {
		for (const tool of IDENTITY_SECOPS_TOOLS) {
			expect(FREE_TOOL_DAILY_LIMITS[tool], `${tool}: public free quota decision`).toBe(0);
			expect(INTENTIONALLY_UNLIMITED_TOOLS.has(tool), `${tool}: must not be intentionally unlimited`).toBe(false);
		}
	});
});

// #746 — partner-tier decision coverage. `TIER_TOOL_DAILY_LIMITS[tier]?.[tool]
// ?? TIER_DAILY_LIMITS[tier]` (src/mcp/execute.ts) makes ABSENCE
// indistinguishable from an intentional flat-limit decision, so 45 of 81 tools
// silently inherited 100k/day. Every TOOL_DEFS entry must now record the
// decision in exactly one place.
describe('partner-tier rate-limit decision coverage audit (#746)', () => {
	const partnerOverrides = TIER_TOOL_DAILY_LIMITS.partner ?? {};

	it('every TOOL_DEFS entry has an explicit partner-tier decision (override XOR intentional-flat)', () => {
		const missing: string[] = [];
		const both: string[] = [];

		for (const tool of TOOLS) {
			const hasOverride = Object.prototype.hasOwnProperty.call(partnerOverrides, tool.name);
			const isFlat = INTENTIONALLY_PARTNER_FLAT_TOOLS.has(tool.name);
			if (!hasOverride && !isFlat) missing.push(tool.name);
			if (hasOverride && isFlat) both.push(tool.name);
		}

		expect(
			missing,
			`tools with NO partner-tier decision (add a TIER_TOOL_DAILY_LIMITS.partner override, or list in INTENTIONALLY_PARTNER_FLAT_TOOLS): ${missing.join(', ')}`,
		).toEqual([]);
		expect(both, `tools with BOTH an override and an intentional-flat declaration (pick one): ${both.join(', ')}`).toEqual([]);
	});

	it('INTENTIONALLY_PARTNER_FLAT_TOOLS membership is a subset of TOOL_DEFS names (catches renames)', () => {
		const validNames = new Set(TOOLS.map((t) => t.name));
		const stale = [...INTENTIONALLY_PARTNER_FLAT_TOOLS].filter((name) => !validNames.has(name));
		expect(stale, `INTENTIONALLY_PARTNER_FLAT_TOOLS contains names not in TOOL_DEFS: ${stale.join(', ')}`).toEqual([]);
	});

	// The partner block legitimately carries the `scan` alias key, which is not a
	// TOOL_DEFS name (tools/call accepts `scan` for `scan_domain`). Any OTHER
	// non-tool key is a typo or a stale rename and must fail.
	it('TIER_TOOL_DAILY_LIMITS keys are TOOL_DEFS names or allowlisted aliases', () => {
		const validNames = new Set(TOOLS.map((t) => t.name));
		for (const [tier, overrides] of Object.entries(TIER_TOOL_DAILY_LIMITS)) {
			const stale = Object.keys(overrides ?? {}).filter((k) => !validNames.has(k) && !RATE_LIMIT_ALIAS_KEYS.has(k));
			expect(stale, `TIER_TOOL_DAILY_LIMITS.${tier} has keys that are neither tools nor aliases: ${stale.join(', ')}`).toEqual([]);
		}
	});

	it('the scan alias tracks its scan_domain target at every tier', () => {
		for (const [tier, overrides] of Object.entries(TIER_TOOL_DAILY_LIMITS)) {
			const o = overrides ?? {};
			if (!('scan' in o) && !('scan_domain' in o)) continue;
			expect(o.scan, `TIER_TOOL_DAILY_LIMITS.${tier}: scan alias must match scan_domain`).toBe(o.scan_domain);
		}
	});

	// Guards the direction that actually costs money: a tool declared "flat is
	// fine" must not thereby end up MORE permissive than the flat tier limit.
	it('intentional-flat tools resolve to exactly the flat partner limit', () => {
		for (const name of INTENTIONALLY_PARTNER_FLAT_TOOLS) {
			const effective = partnerOverrides[name] ?? TIER_DAILY_LIMITS.partner;
			expect(effective, `${name}: effective partner limit`).toBe(TIER_DAILY_LIMITS.partner);
		}
	});
});

describe('legacy identity-secops quota expectations', () => {
	// These four proxy Microsoft Graph reads through bv-web and are auth-required
	// (unauthenticated callers get 401 before dispatch), so their cost bound is
	// the explicit per-principal cap — they must never fall back to the flat
	// 100k partner limit.
	it('identity-secops tools keep explicit paid-tier caps (never flat-inherited)', () => {
		for (const tool of IDENTITY_SECOPS_TOOLS) {
			expect(TIER_TOOL_DAILY_LIMITS.partner?.[tool], `${tool}: explicit partner cap`).toBe(2_000);
			expect(INTENTIONALLY_PARTNER_FLAT_TOOLS.has(tool), `${tool}: must not be declared flat`).toBe(false);
		}
	});
});
