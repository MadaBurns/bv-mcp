// Audit test: the GLOBAL_DAILY_TOOL_LIMIT env override must stay WIRED.
//
// Background (2026-07-08 audit finding): parseGlobalDailyLimit() existed and
// was unit-tested, but no runtime call site used it — the global daily cap was
// un-overridable without a deploy. This audit greps the source so the knob
// can't silently regress to dead code again.

import { describe, it, expect } from 'vitest';

const sources = import.meta.glob(['../../src/index.ts', '../../src/mcp/execute.ts'], {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

function source(suffix: string): string {
	const key = Object.keys(sources).find((k) => k.endsWith(suffix));
	if (!key) throw new Error(`source not globbed: ${suffix}`);
	return sources[key];
}

describe('GLOBAL_DAILY_TOOL_LIMIT env override wiring', () => {
	it('index.ts parses the env override at every executeMcpRequest construction site plus the badge route', () => {
		const idx = source('src/index.ts');
		const parseCalls = idx.match(/parseGlobalDailyLimit\(/g) ?? [];
		// 3 executeMcpRequest construction sites + 1 unauthenticated /badge site.
		expect(parseCalls.length).toBeGreaterThanOrEqual(4);
		// The badge route must not fall back to the raw constant.
		expect(idx).not.toMatch(/checkGlobalDailyLimit\(\s*GLOBAL_DAILY_TOOL_LIMIT/);
	});

	it('execute.ts honors options.globalDailyLimit with the constant as fallback', () => {
		const exec = source('src/mcp/execute.ts');
		expect(exec).toContain('options.globalDailyLimit ?? GLOBAL_DAILY_TOOL_LIMIT');
	});
});
