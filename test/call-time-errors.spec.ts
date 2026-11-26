// SPDX-License-Identifier: BUSL-1.1

/**
 * Call-time errors that tell the caller what to do next: explain_finding with a bad `status`,
 * a URL/email/host:port passed as `domain`, and an unknown tool name with a near-miss.
 */

import { describe, it, expect } from 'vitest';
import { validateDomain } from '../src/lib/sanitize';

async function call(name: string, args: Record<string, unknown> = {}) {
	const { handleToolsCall } = await import('../src/handlers/tools');
	return handleToolsCall({ name, arguments: args });
}

describe('explain_finding status errors', () => {
	it('names the accepted values when status is supplied but not accepted', async () => {
		const result = await call('explain_finding', { checkType: 'spf', status: 'nonsense' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toBe(
			'Error: Invalid status: "nonsense". Use one of: pass, fail, warning, critical, high, medium, low, info.',
		);
	});

	it('echoes only a short printable-ASCII slice of the caller value', async () => {
		const result = await call('explain_finding', { checkType: 'spf', status: `"\\<b>${'x'.repeat(100)}\u0000é` });
		const text = result.content[0].text;
		expect(text).toContain('Invalid status: "');
		expect(text.length).toBeLessThan(200);
		expect(text).not.toContain('\u0000');
		expect(text).not.toContain('é');
	});

	it('keeps the missing-parameters message when a parameter is absent', async () => {
		for (const args of [{ checkType: 'spf' }, { status: 'pass' }, {}]) {
			const result = await call('explain_finding', args);
			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain('Missing required parameters: checkType and status');
		}
	});
});

describe('domain given as a URL, email or host:port', () => {
	const HINT = 'Pass a bare hostname such as example.com, without scheme, path, port or user part';

	it.each(['https://example.com/path', 'http://example.com', 'example.com/path', 'user@example.com', 'example.com:8443', 'example.com:'])(
		'rejects %s with a message naming the fix',
		(input) => {
			expect(validateDomain(input)).toEqual({ valid: false, error: HINT });
		},
	);

	it('surfaces the hint through a tool call, still as a rejection', async () => {
		const result = await call('check_spf', { domain: 'https://example.com/path' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toContain(`Domain validation failed: ${HINT}`);
	});

	it('does not change the outcome for other input', () => {
		expect(validateDomain('example.com')).toEqual({ valid: true });
		expect(validateDomain('::1').error).not.toBe(HINT);
		expect(validateDomain('2001:db8::1').error).not.toBe(HINT);
		expect(validateDomain('127.0.0.1').error).toContain('IP addresses are not allowed');
		expect(validateDomain('exa mple.com').error).toContain('contains invalid characters');
	});
});

describe('unknown tool suggestions', () => {
	it('suggests a close public tool and keeps the Unknown tool prefix', async () => {
		const result = await call('check_spff', { domain: 'example.com' });
		expect(result.isError).toBe(true);
		expect(result.content[0].text).toBe(
			'Error: Unknown tool: check_spff. Call tools/list to see the available tools. Did you mean: check_spf?',
		);
	});

	it('suggests across a missing or extra check_ prefix', async () => {
		const { suggestToolNames } = await import('../src/lib/tool-suggestion');
		expect(suggestToolNames('spf')).toContain('check_spf');
		expect(suggestToolNames('check_scan_domain')).toContain('scan_domain');
	});

	it('offers at most three names, and none when nothing is close', async () => {
		const { suggestToolNames, buildUnknownToolMessage } = await import('../src/lib/tool-suggestion');
		expect(suggestToolNames('check_spff').length).toBeLessThanOrEqual(3);
		expect(suggestToolNames('zzzz_nothing_like_a_tool')).toEqual([]);
		expect(buildUnknownToolMessage('zzzz_nothing_like_a_tool')).toBe(
			'Unknown tool: zzzz_nothing_like_a_tool. Call tools/list to see the available tools.',
		);
		expect(suggestToolNames('x'.repeat(200))).toEqual([]);
	});

	it('never suggests an internal-only tool', async () => {
		const { suggestToolNames, buildUnknownToolMessage } = await import('../src/lib/tool-suggestion');
		const { INTERNAL_ONLY_TOOLS } = await import('../src/lib/config');
		for (const hidden of INTERNAL_ONLY_TOOLS) {
			for (const probe of [hidden.slice(0, -1), `${hidden}x`, hidden.replace('_', '-')]) {
				for (const suggestion of suggestToolNames(probe)) expect(INTERNAL_ONLY_TOOLS.has(suggestion)).toBe(false);
			}
			expect(buildUnknownToolMessage(hidden)).not.toContain(`Did you mean: ${hidden}`);
		}
	});
});
