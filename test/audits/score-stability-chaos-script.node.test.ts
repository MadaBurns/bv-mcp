/** @vitest-environment node */
// SPDX-License-Identifier: BUSL-1.1

import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = join(repoRoot, 'scripts/chaos/score-stability-test.py');

function runProbe(source: string) {
	return spawnSync('python3', ['-c', source, scriptPath], {
		cwd: repoRoot,
		encoding: 'utf8',
	});
}

const loadModule = String.raw`
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("score_stability", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
`;

describe('score stability chaos script', () => {
	it('parses JSON and Streamable HTTP SSE payloads', () => {
		const result = runProbe(`${loadModule}
import json
json_payload = module.parse_mcp_payload('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')
sse_payload = module.parse_mcp_payload('event: message\\nid: 7\\ndata: {"jsonrpc":"2.0","id":2,"result":{"ok":true}}\\n\\n')
print(json.dumps([json_payload, sse_payload]))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual([
			{ jsonrpc: '2.0', id: 1, result: { ok: true } },
			{ jsonrpc: '2.0', id: 2, result: { ok: true } },
		]);
	});

	it('sends the negotiated protocol version and both MCP response media types', () => {
		const result = runProbe(`${loadModule}
import json
print(json.dumps(module.make_headers('session-1')))
`);

		expect(result.status, result.stderr).toBe(0);
		const headers = JSON.parse(result.stdout) as string[];
		expect(headers).toContain('Accept: application/json, text/event-stream');
		expect(headers).toContain('MCP-Protocol-Version: 2025-06-18');
		expect(headers).toContain('Mcp-Session-Id: session-1');
	});

	it('fails closed when any domain errors instead of reporting stable zero', () => {
		const result = runProbe(`${loadModule}
module.DOMAINS = ['example.com', 'example.net']
stable = {
    'example.com': (80, 'B', {'spf': 85}, 1, None),
    'example.net': (None, None, {}, 0, 'HTTP 503'),
}
print(module.compare_multi([stable, stable]))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(result.stdout.trim().endsWith('1')).toBe(true);
		expect(result.stdout).toContain('RESULTS: 1 stable, 0 drifted, 1 errors');
		expect(result.stdout).toContain('FAILED');
	});

	it('rejects empty and malformed MCP response bodies with useful errors', () => {
		const result = runProbe(`${loadModule}
for payload in ['', 'event: message\\ndata: not-json\\n\\n']:
    try:
        module.parse_mcp_payload(payload)
    except ValueError as error:
        print(str(error))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(result.stdout).toContain('empty MCP response body');
		expect(result.stdout).toContain('invalid MCP response body');
	});

	it('extracts structured scan results from an SSE tools/call response', () => {
		const result = runProbe(`${loadModule}
import json
payload = {
    'jsonrpc': '2.0',
    'id': 10,
    'result': {
        'content': [{'type': 'text', 'text': 'scan complete'}],
        'structuredContent': {
            'score': 85,
            'grade': 'B',
            'categoryScores': {'spf': 85, 'ssl': None},
            'findingCounts': {'critical': 0, 'high': 1, 'medium': 2, 'low': 0},
        },
    },
}
module.curl_json = lambda *args, **kwargs: (200, 'event: message\\ndata: ' + json.dumps(payload) + '\\n\\n')
print(json.dumps(module.scan_domain('session-1', 'example.com')))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual(['example.com', 85, 'B', { spf: 85, ssl: null }, 3, null]);
	});

	it('returns exactly the requested domain count when cycling defaults', () => {
		const result = runProbe(`${loadModule}
import json
print(json.dumps(module.load_domains(None, 21)))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(JSON.parse(result.stdout)).toHaveLength(21);
	});

	it('fails closed when an explicit domain file is malformed or empty', () => {
		const result = runProbe(`${loadModule}
import json
import pathlib
import tempfile
with tempfile.TemporaryDirectory() as directory:
    malformed = pathlib.Path(directory) / 'malformed.json'
    malformed.write_text('{not-json')
    empty = pathlib.Path(directory) / 'empty.json'
    empty.write_text('[]')
    for path in [malformed, empty]:
        try:
            module.load_domains(str(path), 10)
        except ValueError as error:
            print(str(error))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(result.stdout).toContain('could not load domain file');
		expect(result.stdout).toContain('domain file must contain at least one domain');
	});

	it('deduplicates an explicit domain file without substituting defaults', () => {
		const result = runProbe(`${loadModule}
import json
import pathlib
import tempfile
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'domains.json'
    path.write_text(json.dumps(['example.com', 'example.com', 'example.net']))
    print(json.dumps(module.load_domains(str(path), 10)))
`);

		expect(result.status, result.stderr).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual(['example.com', 'example.net']);
	});
});
