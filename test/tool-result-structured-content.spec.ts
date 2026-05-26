// SPDX-License-Identifier: BUSL-1.1
//
// Unit + integration coverage for the MCP-standard `structuredContent` field on
// tool-call results. `structuredContent` is a separate, format-independent
// machine-readable channel (an OBJECT per MCP 2025-06-18). The legacy
// `<!-- STRUCTURED_RESULT … -->` comment stays inside `content` for
// backward-compat (full format only).

import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockTxtRecords } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('buildToolResult - structuredContent channel', () => {
	it('wraps a plain object as-is and keeps the human text + STRUCTURED_RESULT comment (full)', async () => {
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const out = buildToolResult('txt', { score: 100 }, 'full');

		expect(out.structuredContent).toEqual({ score: 100 });
		expect(out.content[0].text).toBe('txt');
		// backward-compat comment still appended to content in full format
		expect(out.content.some((c) => c.text.includes('STRUCTURED_RESULT'))).toBe(true);
	});

	it('wraps array data under a `results` key (structuredContent MUST be an object)', async () => {
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const out = buildToolResult('txt', [{ a: 1 }, { a: 2 }], 'full');

		expect(out.structuredContent).toEqual({ results: [{ a: 1 }, { a: 2 }] });
	});

	it('omits structuredContent entirely for null data', async () => {
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const out = buildToolResult('txt', null, 'full');

		expect('structuredContent' in out).toBe(false);
	});

	it('sets structuredContent independent of format (compact has no comment but still carries it)', async () => {
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const out = buildToolResult('txt', { score: 50 }, 'compact');

		// compact strips the embedded comment from content...
		expect(out.content.some((c) => c.text.includes('STRUCTURED_RESULT'))).toBe(false);
		// ...but structuredContent is a separate channel, always present
		expect(out.structuredContent).toEqual({ score: 50 });
	});

	it('wraps a scalar under a `value` key', async () => {
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const out = buildToolResult('txt', 'x', 'full');

		expect(out.structuredContent).toEqual({ value: 'x' });
	});
});

describe('structuredContent - integration through handleToolsCall', () => {
	it('check_spf surfaces a CheckResult-shaped structuredContent object', async () => {
		IN_MEMORY_CACHE.clear();
		mockTxtRecords(['v=spf1 -all']);

		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'check_spf', arguments: { domain: 'example.com' } });

		expect(result.isError).toBeUndefined();
		expect(result.structuredContent).toBeTypeOf('object');
		const sc = result.structuredContent as Record<string, unknown>;
		expect(sc.category).toBe('spf');
		expect(typeof sc.score).toBe('number');
		expect(typeof sc.passed).toBe('boolean');
		expect(Array.isArray(sc.findings)).toBe(true);
	});
});
