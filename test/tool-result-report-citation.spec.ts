// SPDX-License-Identifier: BUSL-1.1
//
// Unit + integration coverage for the citation link-back on tool-call results.
// Domain-bearing, non-error results carry a `source` / `report_url` field pointing
// at the public per-domain scorecard (`/security-report/<domain>`) — the GSI SEO /
// AI-search funnel target. The field is additive and rides through the `.loose()`
// CheckResult outputSchema; non-domain tools and errors get no citation.

import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockTxtRecords } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

afterEach(() => restore());

const EXPECTED = 'https://www.blackveilsecurity.com/security-report/example.com';

describe('buildReportUrl', () => {
	it('builds the public scorecard URL for a domain', async () => {
		const { buildReportUrl } = await import('../src/handlers/tool-formatters');
		expect(buildReportUrl('example.com')).toBe(EXPECTED);
	});

	it('URL-encodes any stray character (defence-in-depth)', async () => {
		const { buildReportUrl } = await import('../src/handlers/tool-formatters');
		expect(buildReportUrl('a b.com')).toBe(
			'https://www.blackveilsecurity.com/security-report/a%20b.com',
		);
	});
});

describe('withReportCitation', () => {
	it('injects source + report_url for a domain-bearing result', async () => {
		const { withReportCitation } = await import('../src/handlers/tool-formatters');
		const out = withReportCitation(
			{ content: [{ type: 'text', text: 'x' }], structuredContent: { score: 80 } },
			'example.com',
		);
		expect(out.structuredContent).toEqual({ score: 80, source: EXPECTED, report_url: EXPECTED });
	});

	it('is a no-op when domain is undefined (non-domain tools)', async () => {
		const { withReportCitation } = await import('../src/handlers/tool-formatters');
		const input = { content: [{ type: 'text' as const, text: 'x' }], structuredContent: { a: 1 } };
		const out = withReportCitation(input, undefined);
		expect(out).toBe(input);
		expect('source' in (out.structuredContent ?? {})).toBe(false);
	});

	it('is a no-op for error results', async () => {
		const { withReportCitation } = await import('../src/handlers/tool-formatters');
		const input: {
			content: { type: 'text'; text: string }[];
			structuredContent?: Record<string, unknown>;
			isError?: boolean;
		} = { content: [{ type: 'text', text: 'x' }], isError: true };
		const out = withReportCitation(input, 'example.com');
		expect(out).toBe(input);
		expect(out.structuredContent).toBeUndefined();
	});

	it('preserves existing structuredContent keys', async () => {
		const { withReportCitation } = await import('../src/handlers/tool-formatters');
		const out = withReportCitation(
			{ content: [], structuredContent: { category: 'spf', passed: true } },
			'example.com',
		);
		const sc = out.structuredContent as Record<string, unknown>;
		expect(sc.category).toBe('spf');
		expect(sc.passed).toBe(true);
		expect(sc.source).toBe(EXPECTED);
	});
});

describe('citation - integration through handleToolsCall', () => {
	it('check_spf carries source + report_url pointing at the domain scorecard', async () => {
		IN_MEMORY_CACHE.clear();
		mockTxtRecords(['v=spf1 -all']);

		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'check_spf', arguments: { domain: 'example.com' } });

		expect(result.isError).toBeUndefined();
		const sc = result.structuredContent as Record<string, unknown>;
		expect(sc.source).toBe(EXPECTED);
		expect(sc.report_url).toBe(EXPECTED);
		// the original CheckResult keys survive alongside the citation
		expect(sc.category).toBe('spf');
	});
});
