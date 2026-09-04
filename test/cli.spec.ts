// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { combineBatchExitCodes, runCli, type CliIo } from '../src/cli/command';

const timestamp = '2026-09-05T00:00:00.000Z';

function scan(domain: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		domain,
		score: 92,
		grade: 'A',
		passed: true,
		measured: true,
		categoryScores: { dnssec: 100 },
		findings: [],
		checkStatuses: { dnssec: 'completed' },
		notApplicableCategories: [],
		inconclusiveCategories: [],
		evidence: { attempted: 1, completed: 1, ratio: 1 },
		evidenceInsufficient: false,
		timestamp,
		scoringModelVersion: '1',
		dnsChecksPackageVersion: '1',
		scoringConfigHash: 'abc',
		...overrides,
	};
}

function rpc(result: unknown, headers: HeadersInit = {}): Response {
	return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200, headers });
}

function harness(files: Record<string, string> = {}, toolResults: unknown[] = []) {
	const stdout: string[] = [];
	const stderr: string[] = [];
	const writes = new Map<string, string>();
	const calls: Array<Record<string, unknown>> = [];
	const responses = [
		rpc({ serverInfo: { name: 'blackveil-dns-mcp', version: '1.2.3' } }, { 'mcp-session-id': 'session-1' }),
		new Response('', { status: 202 }),
		...toolResults.map((result) => rpc(result)),
	];
	const io: CliIo = {
		readTextFile: async (path) => {
			if (!(path in files)) throw new Error('ENOENT');
			return files[path]!;
		},
		writeTextFile: async (path, content, overwrite) => {
			if (!overwrite && writes.has(path)) throw new Error('EEXIST');
			writes.set(path, content);
		},
		stdout: (text) => stdout.push(text),
		stderr: (text) => stderr.push(text),
	};
	const fetchFn = (async (_url, init) => {
		if (init?.body) calls.push(JSON.parse(String(init.body)) as Record<string, unknown>);
		const response = responses.shift();
		if (!response) throw new Error('Unexpected request');
		return response;
	}) as typeof fetch;
	return { io, stdout, stderr, writes, calls, fetchFn };
}

function toolResult(structuredContent: Record<string, unknown>, text = 'ok') {
	return { content: [{ type: 'text', text }], structuredContent };
}

describe('blackveil CLI', () => {
	it('publishes the documented batch precedence', () => {
		expect(combineBatchExitCodes([0, 1])).toBe(1);
		expect(combineBatchExitCodes([1, 4])).toBe(4);
		expect(combineBatchExitCodes([1, 4, 3])).toBe(3);
	});

	it('rejects command-line credentials before any request', async () => {
		const h = harness();
		expect(await runCli(['scan', 'example.com', '--api-key', 'secret'], h)).toBe(2);
		expect(h.calls).toHaveLength(0);
	});

	it('returns incomplete for an ungraded scan without treating null as zero', async () => {
		const h = harness({}, [
			toolResult(scan('example.com', { score: null, grade: null, passed: null, measured: false, evidenceInsufficient: true })),
		]);
		expect(await runCli(['scan', 'example.com', '--format', 'json'], h)).toBe(4);
		expect(JSON.parse(h.stdout.join(''))).toMatchObject({ score: null, grade: null });
	});

	it('returns policy failure only from the remote policy tool', async () => {
		const policy = { domain: 'example.com', passed: false, violations: [{}], inconclusiveRules: [], checkedRules: 1, timestamp };
		const h = harness({}, [toolResult(policy)]);
		expect(await runCli(['policy', 'example.com', '--fail-below', '95', '--format', 'json'], h)).toBe(1);
		expect(h.calls.at(-1)).toMatchObject({ method: 'tools/call', params: { name: 'compare_baseline' } });
	});

	it('uses the paid batch tool without per-domain fallback on denial', async () => {
		const h = harness({ domains: 'one.example\ntwo.example\n' });
		const responses = [
			rpc({ serverInfo: { name: 'blackveil-dns-mcp', version: '1.2.3' } }, { 'mcp-session-id': 'session-1' }),
			new Response('', { status: 202 }),
			new Response(JSON.stringify({ jsonrpc: '2.0', id: 2, error: { code: -32003, message: 'paid access required' } }), { status: 403 }),
		];
		h.fetchFn = (async (_url, init) => {
			if (init?.body) h.calls.push(JSON.parse(String(init.body)) as Record<string, unknown>);
			return responses.shift()!;
		}) as typeof fetch;
		expect(await runCli(['batch', '--file', 'domains'], h)).toBe(3);
		expect(h.calls.filter((call) => JSON.stringify(call).includes('scan_domain'))).toHaveLength(0);
	});

	it('returns incomplete ahead of a measured batch policy failure', async () => {
		const batch = { results: [scan('one.example'), scan('two.example', { score: null, grade: null, passed: null, measured: false })] };
		const policy = { domain: 'one.example', passed: false, violations: [{}], inconclusiveRules: [], checkedRules: 1, timestamp };
		const h = harness({ domains: 'one.example\ntwo.example\n' }, [toolResult(batch), toolResult(policy)]);
		expect(await runCli(['batch', '--file', 'domains', '--fail-below', '95'], h)).toBe(4);
	});

	it('allows checks only when the remote tool declares a public read-only result', async () => {
		const tools = { tools: [{ name: 'check_dnssec', outputSchema: { type: 'object' }, annotations: { readOnlyHint: true } }] };
		const result = { category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'completed' };
		const h = harness({}, [tools, toolResult(result)]);
		expect(await runCli(['check', 'dnssec', 'example.com'], h)).toBe(0);
	});

	it('returns integrity failure before drift makes a remote request', async () => {
		const h = harness({
			baseline: JSON.stringify({
				schemaVersion: 'blackveil-evidence/v1',
				capturedAt: timestamp,
				source: {
					serverName: 'blackveil-dns-mcp',
					serverVersion: '1.2.3',
					endpointOrigin: 'https://dns-mcp.blackveilsecurity.com',
					tool: 'scan_domain',
				},
				result: scan('example.com'),
				integrity: { algorithm: 'sha-256', canonicalization: 'blackveil-cjson/v1', digest: '0'.repeat(64) },
			}),
		});
		expect(await runCli(['drift', 'compare', 'example.com', '--baseline', 'baseline'], h)).toBe(1);
		expect(h.calls).toHaveLength(0);
	});
});
