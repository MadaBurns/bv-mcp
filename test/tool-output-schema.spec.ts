// SPDX-License-Identifier: BUSL-1.1

// Coverage for the MCP `outputSchema` declared on tools whose `structuredContent`
// is a `CheckResult` (v3.3.1). The critical assertion is the round-trip contract:
// a real CheckResult emitted by dispatch MUST validate against the lenient schema,
// or strict clients reject the result.

import { describe, it, expect, afterEach, vi } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';
import { CheckResultOutputSchema, buildCheckResultOutputJsonSchema } from '../src/schemas/check-result-output';
import { handleToolsList } from '../src/handlers/tools';
import { setupFetchMock, createDohResponse, mockTxtRecords } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();
afterEach(() => restore());

/**
 * The 26 special-case tools that return custom shapes (NOT a CheckResult) and
 * therefore must NOT carry an `outputSchema`. Mirrors the EXCLUDE set: everything
 * dispatched outside the TOOL_REGISTRY CheckResult path in handlers/tools.ts.
 */
const NON_CHECK_RESULT_TOOLS = new Set([
	'scan_domain',
	'batch_scan',
	'compare_domains',
	'compare_baseline',
	'generate_fix_plan',
	'generate_spf_record',
	'generate_dmarc_record',
	'generate_dkim_config',
	'generate_mta_sts_policy',
	'get_benchmark',
	'get_provider_insights',
	'assess_spoofability',
	'check_resolver_consistency',
	'explain_finding',
	'map_supply_chain',
	'analyze_drift',
	'validate_fix',
	'generate_rollout_plan',
	'resolve_spf_chain',
	'discover_subdomains',
	'map_compliance',
	'simulate_attack_paths',
	// identity_secops — M365 read tools (custom shape, not CheckResult)
	'query_signins',
	'query_ual',
	'get_ca_policies',
	'assess_coverage',
]);

describe('CheckResult output schema (derived)', () => {
	it('is an object schema requiring category/score/passed/findings', () => {
		const schema = buildCheckResultOutputJsonSchema();
		expect(schema.type).toBe('object');
		expect(new Set(schema.required ?? [])).toEqual(new Set(['category', 'score', 'passed', 'findings']));
		expect(schema.properties.category).toMatchObject({ type: 'string' });
		expect(schema.properties.score).toMatchObject({ type: 'number' });
		expect(schema.properties.passed).toMatchObject({ type: 'boolean' });
		expect(schema.properties.findings).toMatchObject({ type: 'array' });
	});

	it('is lenient — does NOT set additionalProperties: false (extra props allowed)', () => {
		const schema = buildCheckResultOutputJsonSchema();
		expect(schema.additionalProperties).not.toBe(false);
		expect(schema).not.toHaveProperty('$schema');
	});

	it('accepts a CheckResult with wrapper-added fields (checkStatus/partial/metadata)', () => {
		const real = {
			category: 'spf',
			score: 80,
			passed: true,
			findings: [{ category: 'spf', title: 't', severity: 'low', detail: 'd', metadata: { a: 1 } }],
			checkStatus: 'ok',
			partial: false,
			metadata: { foo: 'bar' },
		};
		expect(CheckResultOutputSchema.safeParse(real).success).toBe(true);
	});

	it('rejects a payload missing a required key', () => {
		const bad = { category: 'mx', score: 0, findings: [] };
		expect(CheckResultOutputSchema.safeParse(bad).success).toBe(false);
	});
});

describe('outputSchema declarations on TOOLS', () => {
	it('every non-CheckResult special-case tool has NO outputSchema', () => {
		for (const name of NON_CHECK_RESULT_TOOLS) {
			const tool = TOOLS.find((t) => t.name === name);
			expect(tool, `tool ${name} should exist`).toBeDefined();
			expect(tool?.outputSchema, `tool ${name} must not declare outputSchema`).toBeUndefined();
		}
	});

	it('every other tool (the CheckResult set) HAS an outputSchema equal to the derived schema', () => {
		const derived = buildCheckResultOutputJsonSchema();
		const checkResultTools = TOOLS.filter((t) => !NON_CHECK_RESULT_TOOLS.has(t.name));
		// Sanity: there should be 52 CheckResult tools (78 total − 26 excluded).
		expect(checkResultTools).toHaveLength(53);
		for (const tool of checkResultTools) {
			expect(tool.outputSchema, `tool ${tool.name} must declare outputSchema`).toBeDefined();
			expect(tool.outputSchema).toEqual(derived);
		}
	});

	it('adding outputSchema does not change tool count', () => {
		expect(TOOLS).toHaveLength(79);
	});
});

describe('tools/list emits outputSchema for CheckResult tools only', () => {
	it('CheckResult tools surface outputSchema; excluded tools omit the key', () => {
		const { tools } = handleToolsList();
		const byName = new Map(tools.map((t) => [t.name, t]));

		const spf = byName.get('check_spf') as Record<string, unknown> | undefined;
		expect(spf?.outputSchema).toBeDefined();
		expect((spf?.outputSchema as { type?: string }).type).toBe('object');

		const cymru = byName.get('cymru_asn') as Record<string, unknown> | undefined;
		expect(cymru?.outputSchema).toBeDefined();

		const scan = byName.get('scan_domain') as Record<string, unknown> | undefined;
		expect(scan).toBeDefined();
		expect('outputSchema' in (scan as object)).toBe(false);

		const baseline = byName.get('compare_baseline') as Record<string, unknown> | undefined;
		expect('outputSchema' in (baseline as object)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Round-trip contract: real dispatch output MUST validate against the schema.
// ---------------------------------------------------------------------------

describe('round-trip — real structuredContent validates against CheckResultOutputSchema', () => {
	async function call(name: string, args: Record<string, unknown>) {
		IN_MEMORY_CACHE.clear();
		const { handleToolsCall } = await import('../src/handlers/tools');
		return handleToolsCall({ name, arguments: args });
	}

	it('check_spf', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const result = await call('check_spf', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		const parsed = CheckResultOutputSchema.safeParse(result.structuredContent);
		expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
	});

	it('check_dmarc', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
		const result = await call('check_dmarc', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		const parsed = CheckResultOutputSchema.safeParse(result.structuredContent);
		expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
	});

	it('cymru_asn (no A records → still a CheckResult)', async () => {
		// Empty DoH answers for every query — cymru_asn returns a CheckResult, not an error shape.
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([], []));
		const result = await call('cymru_asn', { domain: 'example.com' });
		expect(result.isError).toBeUndefined();
		const parsed = CheckResultOutputSchema.safeParse(result.structuredContent);
		expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
	});

	it('brand_audit_status unprovisioned (buildCheckResult fallback path)', async () => {
		// No BRAND_AUDIT_DB binding in tests → registry returns buildCheckResult('brand_discovery', ...).
		// Seals the operator-only async tools' structuredContent contract.
		const result = await call('brand_audit_status', { auditId: 'aud_does_not_exist' });
		expect(result.isError).toBeUndefined();
		const parsed = CheckResultOutputSchema.safeParse(result.structuredContent);
		expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
	});
});
