// SPDX-License-Identifier: BUSL-1.1
import http from 'k6/http';
import exec from 'k6/execution';
import { check, fail } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';

const baseUrl = __ENV.BV_LOAD_BASE_URL || 'http://127.0.0.1:8787';
const apiKey = __ENV.BV_LOAD_TEST_KEY;
const domain = __ENV.BV_LOAD_DOMAIN || 'example.com';
const killSwitchUrl = __ENV.BV_LOAD_KILL_SWITCH_URL;
const lane = __ENV.BV_LOAD_LANE || 'edge';
const rate = Number(__ENV.BV_LOAD_RATE || 1);
const duration = __ENV.BV_LOAD_DURATION || '30s';
const region = __ENV.BV_LOAD_REGION || 'local';
const uncachedSuffix = __ENV.BV_LOAD_UNCACHED_SUFFIX;
const summaryPath = __ENV.BV_LOAD_SUMMARY_PATH;

if (!['edge', 'protocol', 'useful', 'heavy', 'mixed'].includes(lane)) throw new Error(`Invalid BV_LOAD_LANE: ${lane}`);
if (lane !== 'edge' && !apiKey) throw new Error('BV_LOAD_TEST_KEY is required for authenticated lanes');
if (rate < 1 || rate > 3200) throw new Error('BV_LOAD_RATE must be between 1 and 3200');

export const options = {
	discardResponseBodies: false,
	summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'count'],
	scenarios: {
		ceiling: {
			executor: 'constant-arrival-rate',
			rate,
			timeUnit: '1s',
			duration,
			preAllocatedVUs: Math.max(10, Math.ceil(rate / 2)),
			maxVUs: Math.max(50, rate * 2),
			exec: 'runLane',
		},
	},
	thresholds: {
		http_req_failed: [{ threshold: 'rate<0.01', abortOnFail: true, delayAbortEval: '30s' }, 'rate<0.001'],
		semantic_failures: [{ threshold: 'rate<0.01', abortOnFail: true, delayAbortEval: '30s' }, 'rate<0.001'],
		lightweight_latency: [{ threshold: 'p(95)<2000', abortOnFail: true, delayAbortEval: '30s' }, 'p(95)<500'],
		heavy_latency: [{ threshold: 'p(95)<30000', abortOnFail: true, delayAbortEval: '30s' }, 'p(95)<10000'],
	},
	tags: { region, lane },
};

const semanticFailures = new Rate('semantic_failures');
const schemaFailures = new Counter('schema_failures');
const lightweightLatency = new Trend('lightweight_latency', true);
const heavyLatency = new Trend('heavy_latency', true);
const responseBytes = new Trend('response_bytes');
const quotaResponses = new Counter('quota_responses');
const wafResponses = new Counter('waf_responses');
let sessionId;
let requestId = 1;

function headers(extra = {}) {
	return {
		'Content-Type': 'application/json',
		Accept: 'application/json, text/event-stream',
		Authorization: apiKey ? `Bearer ${apiKey}` : undefined,
		'MCP-Protocol-Version': '2025-06-18',
		'User-Agent': 'bv-load-test/1.0',
		...extra,
	};
}

function parseMcp(response) {
	responseBytes.add(String(response.body || '').length);
	if (response.status === 429) quotaResponses.add(1);
	if ([403, 1020].includes(response.status) || String(response.body).toLowerCase().includes('cloudflare')) wafResponses.add(1);
	let payload = response.body;
	if ((response.headers['Content-Type'] || '').includes('text/event-stream')) {
		const events = String(payload)
			.split('\n')
			.filter((line) => line.startsWith('data:'))
			.map((line) => line.slice(5).trim())
			.filter((line) => line && line !== '[DONE]');
		if (events.length === 0) throw new Error('SSE response contained no data event');
		payload = events.at(-1);
	}
	const parsed = JSON.parse(payload);
	if (parsed.error || parsed.result?.isError) throw new Error(parsed.error?.message || 'MCP result isError');
	if (parsed.jsonrpc !== '2.0' || parsed.id === undefined || !parsed.result) throw new Error('Invalid MCP response envelope');
	return parsed;
}

function initialize() {
	const response = http.post(
		`${baseUrl}/mcp`,
		JSON.stringify({
			jsonrpc: '2.0',
			id: requestId++,
			method: 'initialize',
			params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bv-load-test', version: '1.0' } },
		}),
		{ headers: headers(), tags: { workload: 'initialize' } },
	);
	parseMcp(response);
	sessionId = response.headers['Mcp-Session-Id'];
	if (!sessionId) throw new Error('initialize omitted mcp-session-id');
}

function mcp(method, params, workload, heavy = false) {
	if (!sessionId) initialize();
	const response = http.post(
		`${baseUrl}/mcp`,
		JSON.stringify({ jsonrpc: '2.0', id: requestId++, method, params }),
		{ headers: headers({ 'Mcp-Session-Id': sessionId }), tags: { workload } },
	);
	try {
		const parsed = parseMcp(response);
		if (method === 'tools/list' && !Array.isArray(parsed.result.tools)) throw new Error('tools/list omitted tools array');
		if (method === 'tools/call' && !Array.isArray(parsed.result.content)) throw new Error('tools/call omitted content array');
		semanticFailures.add(false, { workload });
		(heavy ? heavyLatency : lightweightLatency).add(response.timings.duration, { workload });
	} catch (error) {
		semanticFailures.add(true, { workload });
		schemaFailures.add(1, { workload });
		fail(`${workload}: ${error.message}`);
	}
}

function pollKillSwitch() {
	if (!killSwitchUrl || __ITER % 20 !== 0) return;
	const response = http.get(killSwitchUrl, { responseType: 'text', tags: { workload: 'kill_switch' } });
	if (response.status !== 200 || String(response.body).trim().toLowerCase() !== 'run') exec.test.abort('Global kill switch activated');
}

export function runLane() {
	pollKillSwitch();
	if (lane === 'edge') {
		const response = http.get(`${baseUrl}/health`, { tags: { workload: 'health' } });
		const ok = check(response, { 'health is correct': (r) => r.status === 200 && r.json('status') === 'ok' });
		semanticFailures.add(!ok, { workload: 'health' });
		lightweightLatency.add(response.timings.duration, { workload: 'health' });
		return;
	}
	if (lane === 'protocol') return mcp('tools/list', {}, 'tools_list');
	if (lane === 'useful') {
		const target = uncachedSuffix && __ITER % 3 === 0 ? `load-${__VU}-${__ITER}.${uncachedSuffix}` : domain;
		return mcp('tools/call', { name: 'check_spf', arguments: { domain: target } }, target === domain ? 'check_spf_cached' : 'check_spf_uncached');
	}
	if (lane === 'heavy') return mcp('tools/call', { name: 'scan_domain', arguments: { domain, format: 'compact' } }, 'scan_domain', true);

	const pick = Math.random();
	if (pick < 0.05) return initialize();
	if (pick < 0.15) return mcp('tools/list', {}, 'tools_list');
	if (pick < 0.7) return mcp('tools/call', { name: 'check_spf', arguments: { domain } }, 'check_spf');
	if (pick < 0.9) return mcp('tools/call', { name: 'scan_domain', arguments: { domain, format: 'compact' } }, 'scan_domain', true);
	return mcp('tools/call', { name: 'osint_investigate_status', arguments: { investigationId: 'synthetic-not-found' } }, 'osint_status');
}

export function handleSummary(data) {
	if (!summaryPath) return {};
	return { [summaryPath]: JSON.stringify(data, null, 2) };
}
