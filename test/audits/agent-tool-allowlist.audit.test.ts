import { describe, it, expect } from 'vitest';
import { AGENT_ALLOWED_TOOLS, AGENT_CALLER_HEADER, isAgentCaller, isAgentAllowedTool } from '../../src/lib/config';
import { TOOLS } from '../../src/schemas/tool-definitions';

const EXPECTED_AGENT_TOOLS = [
	'scan_domain',
	'check_spf',
	'check_dkim',
	'check_dmarc',
	'check_dnssec',
	'check_ssl',
	'check_mx',
	'check_mta_sts',
	'check_caa',
	'check_http_security',
	'explain_finding',
	'compare_baseline',
	'get_benchmark',
].sort();

describe('agent-chat tool allowlist SSOT', () => {
	it('contains exactly the 13 curated tools', () => {
		expect([...AGENT_ALLOWED_TOOLS].sort()).toEqual(EXPECTED_AGENT_TOOLS);
	});

	it('every allowlisted tool exists in TOOL_DEFS', () => {
		const known = new Set(TOOLS.map((t) => t.name));
		for (const name of AGENT_ALLOWED_TOOLS) {
			expect(known.has(name), `${name} missing from TOOLS`).toBe(true);
		}
	});

	it('every allowlisted tool is read-only (no mutating tool can slip in)', () => {
		const byName = new Map(TOOLS.map((t) => [t.name, t]));
		for (const name of AGENT_ALLOWED_TOOLS) {
			expect(byName.get(name)?.annotations?.readOnlyHint, `${name} is not read-only`).toBe(true);
		}
	});

	it('header constant and predicates behave', () => {
		expect(AGENT_CALLER_HEADER).toBe('x-bv-caller');
		expect(isAgentCaller('agent-chat')).toBe(true);
		expect(isAgentCaller('something-else')).toBe(false);
		expect(isAgentCaller(null)).toBe(false);
		expect(isAgentAllowedTool('scan_domain')).toBe(true);
		expect(isAgentAllowedTool('query_signins')).toBe(false);
	});
});
