// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { combineBatchExitCodes, runCli, type CliIo } from '../src/cli/command';
import { createEvidenceSnapshot } from '../src/cli/evidence';

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

function rpc(result: unknown, headers: HeadersInit = {}, id = 1): Response {
	return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), { status: 200, headers });
}

const initialized = { protocolVersion: '2025-06-18', serverInfo: { name: 'blackveil-dns-mcp', version: '1.2.3' } };

function harness(files: Record<string, string> = {}, toolResults: unknown[] = []) {
	const stdout: string[] = [];
	const stderr: string[] = [];
	const writes = new Map<string, string>();
	const calls: Array<Record<string, unknown>> = [];
	const responses = [
		rpc(initialized, { 'mcp-session-id': 'session-1' }),
		new Response('', { status: 202 }),
		...toolResults.map((result, index) => rpc(result, {}, index + 2)),
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

async function baselineEvidence(overrides: Record<string, unknown> = {}): Promise<string> {
	return JSON.stringify(
		await createEvidenceSnapshot({
			capturedAt: timestamp,
			serverName: 'synthetic-server',
			serverVersion: '1',
			endpointOrigin: 'https://example.test',
			tool: 'scan_domain',
			result: scan('example.com', overrides),
		}),
	);
}

describe('blackveil CLI', () => {
	it('publishes the documented batch precedence', () => {
		expect(combineBatchExitCodes([0, 1])).toBe(1);
		expect(combineBatchExitCodes([1, 4])).toBe(4);
		expect(combineBatchExitCodes([1, 4, 3])).toBe(3);
		expect(combineBatchExitCodes([2, 0])).toBe(2);
		expect(combineBatchExitCodes([1, 2])).toBe(1);
		expect(combineBatchExitCodes([0, 0])).toBe(0);
		expect(combineBatchExitCodes([])).toBe(0);
	});

	it('rejects command-line credentials before any request', async () => {
		const h = harness();
		expect(await runCli(['scan', 'example.com', '--api-key', 'secret'], h)).toBe(2);
		expect(h.calls).toHaveLength(0);
	});

	it('starts the shared deadline before command input is read', async () => {
		let now = 1_000;
		const h = harness({ domains: 'example.com\n' });
		const originalRead = h.io.readTextFile;
		h.io.readTextFile = async (path) => {
			const value = await originalRead(path);
			now = 46_001;
			return value;
		};
		expect(await runCli(['batch', '--file', 'domains'], { ...h, nowMs: () => now })).toBe(3);
		expect(h.calls).toHaveLength(0);
		expect(h.stderr.join('')).toContain('command deadline exceeded');
	});

	it('returns incomplete for an ungraded scan without treating null as zero', async () => {
		const h = harness({}, [
			toolResult(scan('example.com', { score: null, grade: null, passed: null, measured: false, evidenceInsufficient: true })),
		]);
		expect(await runCli(['scan', 'example.com', '--format', 'json'], h)).toBe(4);
		expect(JSON.parse(h.stdout.join(''))).toMatchObject({ score: null, grade: null });
	});

	it.each([
		{ checkStatuses: { dnssec: 'timeout' }, inconclusiveCategories: [] },
		{ checkStatuses: { dnssec: 'completed' }, inconclusiveCategories: ['dnssec'] },
	])('returns incomplete for non-completed scan evidence', async (overrides) => {
		const h = harness({}, [toolResult(scan('example.com', overrides))]);
		expect(await runCli(['scan', 'example.com'], h)).toBe(4);
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
			rpc(initialized, { 'mcp-session-id': 'session-1' }),
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

	it('returns incomplete for a non-completed check even when partial is absent', async () => {
		const tools = { tools: [{ name: 'check_dnssec', outputSchema: { type: 'object' }, annotations: { readOnlyHint: true } }] };
		const result = { category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'error' };
		const h = harness({}, [tools, toolResult(result)]);
		expect(await runCli(['check', 'dnssec', 'example.com'], h)).toBe(4);
	});

	it('sanitizes and emits every remote tool error diagnostic', async () => {
		const h = harness({}, [{ content: [{ type: 'text', text: '\u001b[31mdenied\r\nretry\u0000' }], isError: true }]);
		expect(await runCli(['scan', 'example.com'], h)).toBe(3);
		expect(h.stderr.join('')).toBe('scan_domain: denied\nretry\n');
		expect(h.stdout).toHaveLength(0);
	});

	it.each([
		{ checkStatuses: { dnssec: 'timeout' }, categoryScores: { dnssec: null } },
		{ checkStatuses: { dnssec: 'error' }, categoryScores: { dnssec: null } },
		{ inconclusiveCategories: ['dnssec'] },
		{ evidenceInsufficient: true },
		{ measured: false },
		{ error: 'batch_budget_exceeded' },
		{ score: null, grade: null, passed: null, measured: false },
	])('rejects an incomplete drift baseline before contacting the server: %j', async (overrides) => {
		const drift = { domain: 'example.com', classification: 'stable', scoreDelta: 0, gradeChange: { from: 'A', to: 'A' }, timestamp };
		const h = harness({ baseline: await baselineEvidence(overrides) }, [toolResult(drift)]);
		expect(await runCli(['drift', 'compare', 'example.com', '--baseline', 'baseline'], h)).toBe(4);
		expect(h.calls).toHaveLength(0);
		expect(h.stdout).toHaveLength(0);
		expect(h.stderr.join('')).toContain('Drift baseline contains incomplete scan evidence');
	});

	it.each([
		{ score: 92, grade: 'A', passed: true },
		{ score: 30, grade: 'F', passed: false },
	])('compares a complete baseline even when its security verdict fails: %j', async (overrides) => {
		const drift = {
			domain: 'example.com',
			classification: 'stable',
			scoreDelta: 0,
			gradeChange: { from: overrides.grade, to: overrides.grade },
			timestamp,
		};
		const h = harness({ baseline: await baselineEvidence(overrides) }, [toolResult(drift)]);
		expect(await runCli(['drift', 'compare', 'example.com', '--baseline', 'baseline', '--format', 'json'], h)).toBe(0);
		expect(h.calls.at(-1)).toMatchObject({
			method: 'tools/call',
			params: {
				name: 'analyze_drift',
				arguments: {
					domain: 'example.com',
					baseline: JSON.stringify({ overall: overrides.score, grade: overrides.grade, categoryScores: { dnssec: 100 }, findings: [] }),
				},
			},
		});
		expect(JSON.parse(h.stdout.join(''))).toMatchObject(drift);
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

describe('blackveil CLI output rendering', () => {
	it('prints the remote human-readable text for the default format', async () => {
		const h = harness({}, [toolResult(scan('example.com'), 'Score 92 (A) for example.com')]);
		expect(await runCli(['scan', 'example.com'], h)).toBe(0);
		expect(h.stdout).toEqual(['Score 92 (A) for example.com\n']);
	});

	it('fails with a protocol error when the human format has no text content', async () => {
		const h = harness({}, [{ content: [{ type: 'image' }], structuredContent: scan('example.com') }]);
		expect(await runCli(['scan', 'example.com'], h)).toBe(3);
		expect(h.stderr.join('')).toContain('MCP tool result omitted human-readable text');
		expect(h.stdout).toHaveLength(0);
	});

	it('prints pretty JSON of the structured result for --format json', async () => {
		const structured = scan('example.com');
		const h = harness({}, [toolResult(structured)]);
		expect(await runCli(['scan', 'example.com', '--format', 'json'], h)).toBe(0);
		expect(h.stdout).toEqual([`${JSON.stringify(structured, null, 2)}\n`]);
	});

	it('prints one JSON line per batch entry for --format ndjson', async () => {
		const batch = { results: [scan('one.example'), scan('two.example')] };
		const h = harness({ domains: 'one.example\ntwo.example\n' }, [toolResult(batch)]);
		expect(await runCli(['batch', '--file', 'domains', '--format', 'ndjson'], h)).toBe(0);
		expect(h.stdout).toEqual([`${JSON.stringify(batch.results[0])}\n${JSON.stringify(batch.results[1])}\n`]);
	});

	it('prints a single compact JSON line for --format ndjson when the result has no results array', async () => {
		const structured = scan('example.com');
		const h = harness({}, [toolResult(structured)]);
		expect(await runCli(['scan', 'example.com', '--format', 'ndjson'], h)).toBe(0);
		expect(h.stdout).toEqual([`${JSON.stringify(structured)}\n`]);
	});

	it('wraps the result in a verifiable evidence snapshot with server provenance for --format evidence', async () => {
		const structured = scan('example.com');
		const h = harness({}, [toolResult(structured)]);
		const exit = await runCli(['scan', 'example.com', '--format', 'evidence'], { ...h, now: () => new Date(timestamp) });
		expect(exit).toBe(0);

		const snapshot = JSON.parse(h.stdout.join('')) as {
			capturedAt: string;
			source: { serverName: string; serverVersion: string; endpointOrigin: string; tool: string };
			result: unknown;
		};
		expect(snapshot.capturedAt).toBe(timestamp);
		expect(snapshot.source).toEqual({
			serverName: 'blackveil-dns-mcp',
			serverVersion: '1.2.3',
			endpointOrigin: 'https://dns-mcp.blackveilsecurity.com',
			tool: 'scan_domain',
		});
		expect(snapshot.result).toEqual(structured);
		// The emitted snapshot round-trips through the CLI's own integrity verifier.
		const verify = harness({ snapshot: h.stdout.join('') });
		expect(await runCli(['evidence', 'verify', 'snapshot'], verify)).toBe(0);
	});

	it('stamps the evidence snapshot from the real clock when no clock is injected', async () => {
		const h = harness({}, [toolResult(scan('example.com'))]);
		const before = Date.now();
		expect(await runCli(['scan', 'example.com', '--format', 'evidence'], h)).toBe(0);
		const capturedAt = Date.parse((JSON.parse(h.stdout.join('')) as { capturedAt: string }).capturedAt);
		expect(capturedAt).toBeGreaterThanOrEqual(before);
		expect(capturedAt).toBeLessThanOrEqual(Date.now());
	});
});

describe('blackveil CLI --out handling', () => {
	it('writes the rendered output to the file instead of stdout and reports it on stderr', async () => {
		const h = harness({}, [toolResult(scan('example.com'), 'report text')]);
		expect(await runCli(['scan', 'example.com', '--out', 'report.txt'], h)).toBe(0);
		expect(h.writes.get('report.txt')).toBe('report text\n');
		expect(h.stdout).toHaveLength(0);
		expect(h.stderr.join('')).toBe('Wrote report.txt\n');
	});

	it('refuses to overwrite an existing file without --force and reports a usage error', async () => {
		const h = harness({}, [toolResult(scan('example.com'), 'new text')]);
		h.writes.set('report.txt', 'old text');
		expect(await runCli(['scan', 'example.com', '--out', 'report.txt'], h)).toBe(2);
		expect(h.writes.get('report.txt')).toBe('old text');
		expect(h.stderr.join('')).toContain('Could not write report.txt: EEXIST');
		expect(h.stdout).toHaveLength(0);
	});

	it('overwrites an existing file when --force is passed', async () => {
		const h = harness({}, [toolResult(scan('example.com'), 'new text')]);
		h.writes.set('report.txt', 'old text');
		expect(await runCli(['scan', 'example.com', '--out', 'report.txt', '--force'], h)).toBe(0);
		expect(h.writes.get('report.txt')).toBe('new text\n');
	});

	it('uses a generic message when the write fails with a non-Error value', async () => {
		const h = harness({}, [toolResult(scan('example.com'))]);
		h.io.writeTextFile = async () => {
			throw 'disk full';
		};
		expect(await runCli(['scan', 'example.com', '--out', 'report.txt'], h)).toBe(2);
		expect(h.stderr.join('')).toContain('Could not write report.txt: write failed');
	});
});
