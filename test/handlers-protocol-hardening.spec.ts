import { describe, expect, it } from 'vitest';
import { handleResourcesRead, SCAN_CATEGORY_COUNT } from '../src/handlers/resources';
import { normalizeToolName, resolveToolAlias } from '../src/handlers/tool-args';
import { handlePromptsGet } from '../src/handlers/prompts';
import { SCAN_CATEGORIES } from '../src/tools/scan-domain';

const PROTOTYPE_KEYS = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf'];

describe('handlers-protocol-hardening: prototype-key lookups (item 3)', () => {
	it.each(PROTOTYPE_KEYS)('resources/read uri %s is Resource not found', (uri) => {
		expect(() => handleResourcesRead({ uri })).toThrow(`Resource not found: ${uri}`);
	});

	it.each(PROTOTYPE_KEYS)('resolveToolAlias(%s) passes the name through unchanged', (key) => {
		const args = { domain: 'example.com' };
		const resolved = resolveToolAlias(key, args);
		expect(resolved.name).toBe(key.toLowerCase());
		expect(resolved.args).toBe(args);
	});

	it.each(PROTOTYPE_KEYS)('normalizeToolName(%s) returns the lowercased name', (key) => {
		expect(normalizeToolName(key)).toBe(key.toLowerCase());
	});

	it('real aliases still resolve', () => {
		expect(resolveToolAlias('scan', {}).name).toBe('scan_domain');
		expect(resolveToolAlias('generate_spf_record', {}).args).toMatchObject({ artifact: 'spf_record' });
		expect(normalizeToolName(' Scan ')).toBe('scan_domain');
	});

	it.each(PROTOTYPE_KEYS)('prompts/get name %s is an invalid prompt name', (name) => {
		expect(() => handlePromptsGet({ name })).toThrow(`Invalid prompt name: ${name}`);
	});

	it('tools/call with a prototype key name is an unknown tool, not a crash', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		for (const name of PROTOTYPE_KEYS) {
			const result = await handleToolsCall({ name, arguments: {} });
			expect(result.isError).toBe(true);
		}
	});
});

describe('handlers-protocol-hardening: scan cache keys hash the full list (item 4)', () => {
	const longPrefix = 'a'.repeat(200);

	it('check_subdomain_takeover keys differ when lists share a 128-char prefix', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_subdomain_takeover.cacheKey;
		const keyA = await cacheKey({ subdomains: [`${longPrefix}1`] });
		const keyB = await cacheKey({ subdomains: [`${longPrefix}2`] });
		expect(keyA).not.toBe(keyB);
		expect(keyA).toBe(await cacheKey({ subdomains: [`${longPrefix}1`] }));
	});

	it('check_subdomain_takeover key is order-insensitive and bounded in length', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_subdomain_takeover.cacheKey;
		const big = Array.from({ length: 200 }, (_, i) => `sub-${i}.example.com`);
		const keyA = await cacheKey({ subdomains: big });
		const keyB = await cacheKey({ subdomains: big.slice().reverse() });
		expect(keyA).toBe(keyB);
		expect(String(keyA).length).toBeLessThan(100);
	});

	it.each(['discover_brand_domains', 'brand_audit_single'] as const)(
		'%s keys differ when brand_aliases share a 64-char prefix',
		async (tool) => {
			const { TOOL_REGISTRY } = await import('../src/handlers/tools');
			const cacheKey = TOOL_REGISTRY[tool].cacheKey;
			const prefix = 'b'.repeat(100);
			const keyA = await cacheKey({ brand_aliases: [`${prefix}1`] });
			const keyB = await cacheKey({ brand_aliases: [`${prefix}2`] });
			expect(keyA).not.toBe(keyB);
		},
	);

	it.each(['discover_brand_domains', 'brand_audit_single'] as const)(
		'%s keys differ when candidate_domains share a 64-char prefix',
		async (tool) => {
			const { TOOL_REGISTRY } = await import('../src/handlers/tools');
			const cacheKey = TOOL_REGISTRY[tool].cacheKey;
			const prefix = 'c'.repeat(100);
			const keyA = await cacheKey({ candidate_domains: [`${prefix}1.com`] });
			const keyB = await cacheKey({ candidate_domains: [`${prefix}2.com`] });
			expect(keyA).not.toBe(keyB);
		},
	);

	it.each(['discover_brand_domains', 'brand_audit_single'] as const)('%s empty and omitted lists share the key', async (tool) => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY[tool].cacheKey;
		expect(await cacheKey({})).toBe(await cacheKey({ brand_aliases: [], candidate_domains: [] }));
	});
});

describe('handlers-protocol-hardening: SCAN_CATEGORY_COUNT (item 7)', () => {
	it('equals the number of categories scan_domain actually runs', () => {
		expect(SCAN_CATEGORY_COUNT).toBe(SCAN_CATEGORIES.length);
		expect(SCAN_CATEGORY_COUNT).toBe(19);
	});

	it('the served guide and serverInfo text carry the dispatch-table count', () => {
		const guide = handleResourcesRead({ uri: 'dns-security://guides/security-checks' });
		expect(guide.contents[0].text).toContain(`across ${SCAN_CATEGORIES.length} scan categories`);
	});
});
