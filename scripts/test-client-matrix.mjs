#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
//
// scripts/test-client-matrix.mjs
// Client-matrix production test harness: calls every deployed MCP tool from
// every MCP client type and asserts the per-client output-format contract.
// See docs/superpowers/specs/2026-05-24-client-matrix-test-harness-design.md
//
// Usage:
//   BV_API_KEY=... node scripts/test-client-matrix.mjs            # full run vs prod
//   node scripts/test-client-matrix.mjs --self-test               # offline assertion-helper checks
//   BV_API_KEY=... node scripts/test-client-matrix.mjs --dry-run  # print planned matrix (1 tools/list call)
//   BV_API_KEY=... BV_MCP_ENDPOINT=http://localhost:8787/mcp node scripts/test-client-matrix.mjs
//   BV_API_KEY=... node scripts/test-client-matrix.mjs --json out.json
import process from 'node:process';
import fs from 'node:fs';

// --- Config ---------------------------------------------------------------
const EP = process.env.BV_MCP_ENDPOINT || 'https://dns-mcp.blackveilsecurity.com/mcp';
const API_KEY = process.env.BV_API_KEY;
const TARGET = process.env.TARGET_DOMAIN || 'blackveilsecurity.com';
const CONCURRENCY = parseInt(process.env.MATRIX_CONCURRENCY || '4', 10);
const DRY_RUN = process.argv.includes('--dry-run');
const SELF_TEST = process.argv.includes('--self-test');
const jsonIdx = process.argv.indexOf('--json');
const JSON_OUT = jsonIdx >= 0 ? process.argv[jsonIdx + 1] : null;
if (jsonIdx >= 0 && !JSON_OUT) {
	console.error('Error: --json requires a path argument.');
	process.exit(1);
}

// --- Client UA tables -----------------------------------------------------
const INTERACTIVE_UAS = {
	claude_code: 'claude-code/2.1.0',
	claude_mobile: 'claude-mobile/1.0',
	cursor: 'cursor/0.45.0',
	vscode: 'vscode/1.90.0',
	windsurf: 'windsurf/2.0',
	claude_desktop: 'claude-desktop/1.0',
};
const NONINTERACTIVE_UAS = {
	mcp_remote: 'mcp-remote/1.0.0',
	blackveil_dns_action: 'blackveil-dns-action/1.2.0',
	bv_claude_dns_proxy: 'bv-claude-dns-proxy/1.1.0',
	bv_load_test: 'bv-load-test/1.0',
	unknown: 'matrix-harness-unknown/1.0', // matches no pattern -> 'unknown' -> non-interactive
};
const REP_INTERACTIVE_UA = INTERACTIVE_UAS.claude_code;
const REP_NONINTERACTIVE_UA = NONINTERACTIVE_UAS.mcp_remote;

// Tools that mutate/produce IDs — run once in setup/teardown, not the dual sweep.
// Prod (v3.0.0/#204) exposes register/delete/list_brand_audit_watches as separate tools.
const MUTATING_TOOLS = new Set(['register_brand_audit_watch', 'brand_audit_batch_start', 'delete_brand_audit_watch']);
// `format` arg is output-mode (json|markdown|both), not verbosity — skip Invariant B.
const FORMAT_SPECIAL = new Set(['brand_audit_single', 'brand_audit_batch_start']);
// Envelope may legitimately be isError (not-ready / scan-only / no-baseline) — record, don't fail.
const RECORD_ONLY = new Set(['check_subdomain_takeover', 'brand_audit_get_report', 'analyze_drift']);

// --- Pure result helpers --------------------------------------------------
function resultText(result) {
	if (!result || !Array.isArray(result.content)) return '';
	return result.content.map((c) => (c && typeof c.text === 'string' ? c.text : '')).join('\n');
}

function hasStructuredResult(result) {
	return resultText(result).includes('STRUCTURED_RESULT');
}

function extractStructured(result) {
	const m = resultText(result).match(/<!-- STRUCTURED_RESULT\n([\s\S]*?)\nSTRUCTURED_RESULT -->/);
	if (!m) return null;
	try {
		return JSON.parse(m[1]);
	} catch {
		return null;
	}
}

function deepFind(obj, keys, depth = 0) {
	if (!obj || typeof obj !== 'object' || depth > 6) return null;
	for (const k of keys) if (typeof obj[k] === 'string' && obj[k]) return obj[k];
	for (const v of Object.values(obj)) {
		const r = deepFind(v, keys, depth + 1);
		if (r) return r;
	}
	return null;
}

function extractId(result, keys) {
	const s = extractStructured(result);
	const fromJson = s && deepFind(s, keys);
	if (fromJson) return fromJson;
	const text = resultText(result);
	for (const k of keys) {
		// JSON form: "auditId":"<uuid>"
		const json = text.match(new RegExp(`"${k}"\\s*:\\s*"([^"]+)"`));
		if (json) return json[1];
		// Finding detail form (e.g. brand_audit_batch_start with format:'json'): auditId=<uuid>
		const kv = text.match(new RegExp(`\\b${k}\\s*[=:]\\s*"?([A-Za-z0-9._-]{4,})`));
		if (kv) return kv[1];
	}
	return null;
}

// callRes = { result } on success, or { error, code } on JSON-RPC error.
function checkEnvelope(callRes) {
	if (callRes.error) return { ok: false, reason: `rpc_error: ${callRes.error}${callRes.code ? ` (${callRes.code})` : ''}` };
	const r = callRes.result;
	if (!r || !Array.isArray(r.content) || r.content.length === 0) return { ok: false, reason: 'no_content' };
	if (r.content[0].type !== 'text') return { ok: false, reason: `content_type=${r.content[0].type}` };
	if (r.isError) return { ok: false, reason: `isError: ${resultText(r).slice(0, 120)}` };
	return { ok: true };
}

// Classify a tool tested in both classes. status: PASS | FAIL | INVARIANT | RECORD.
function classifyTool({ name, ri, rn }) {
	const envI = checkEnvelope(ri);
	const envN = checkEnvelope(rn);
	const markerI = ri.result ? hasStructuredResult(ri.result) : false;
	const markerN = rn.result ? hasStructuredResult(rn.result) : false;
	if (markerI) return { name, status: 'FAIL', reason: 'invariant_A: interactive response contains STRUCTURED_RESULT' };
	if (RECORD_ONLY.has(name)) {
		return { name, status: 'RECORD', reason: `recorded (I:${envI.ok ? 'ok' : envI.reason}, N:${envN.ok ? 'ok' : envN.reason})` };
	}
	if (!envI.ok) return { name, status: 'FAIL', reason: `interactive envelope: ${envI.reason}` };
	if (!envN.ok) return { name, status: 'FAIL', reason: `non-interactive envelope: ${envN.reason}` };
	if (FORMAT_SPECIAL.has(name)) return { name, status: 'PASS', reason: 'format-special (envelope + invariant A only)' };
	if (markerN && !markerI) return { name, status: 'PASS', reason: 'format-discriminated' };
	if (!markerN && !markerI) return { name, status: 'INVARIANT', reason: 'format-invariant (no marker in either class)' };
	return { name, status: 'PASS' };
}

// --- MCP network layer ----------------------------------------------------
function headers(ua, sid) {
	const h = {
		'Authorization': `Bearer ${API_KEY}`,
		'Content-Type': 'application/json',
		'Accept': 'application/json, text/event-stream',
		'User-Agent': ua,
	};
	if (sid) h['Mcp-Session-Id'] = sid;
	return h;
}

function parseSse(text) {
	const line = text.split('\n').find((l) => l.startsWith('data: '));
	if (!line) return null;
	try {
		return JSON.parse(line.slice(6));
	} catch {
		return null;
	}
}

// Open a session for a given client UA: initialize -> capture id -> initialized.
async function createSession(ua) {
	const res = await fetch(EP, {
		method: 'POST',
		headers: headers(ua),
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: ua, version: '1' } },
		}),
	});
	const sid = res.headers.get('mcp-session-id') ?? '';
	await res.text(); // drain SSE body
	if (!sid) throw new Error(`initialize returned no Mcp-Session-Id (status ${res.status}) for UA "${ua}"`);
	const ack = await fetch(EP, {
		method: 'POST',
		headers: headers(ua, sid),
		body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
	});
	await ack.text(); // drain
	return { ua, sid };
}

// Single JSON-RPC call on a session. Retries once on rate-limit (-32029).
async function rpc(session, method, params, { retry = true } = {}) {
	let res;
	try {
		res = await fetch(EP, {
			method: 'POST',
			headers: headers(session.ua, session.sid),
			body: JSON.stringify({ jsonrpc: '2.0', id: Math.floor(Math.random() * 1e9), method, params }),
		});
	} catch (err) {
		return { error: `network: ${err.message}` };
	}
	const text = await res.text();
	const parsed = parseSse(text);
	if (!parsed) return { httpStatus: res.status, error: 'no_data_frame', raw: text.slice(0, 200) };
	if (parsed.error) {
		if (retry && parsed.error.code === -32029) {
			const parsedWait = parseInt(res.headers.get('retry-after') || '2', 10);
			const waitMs = (Number.isFinite(parsedWait) ? parsedWait : 2) * 1000;
			await new Promise((r) => setTimeout(r, waitMs));
			return rpc(session, method, params, { retry: false });
		}
		return { httpStatus: res.status, error: parsed.error.message, code: parsed.error.code };
	}
	return { httpStatus: res.status, result: parsed.result };
}

const callTool = (session, name, args, opts) => rpc(session, 'tools/call', { name, arguments: args }, opts);

// Bounded concurrency map (from scripts/chaos-100-domains.mjs).
async function mapConcurrent(items, limit, fn) {
	const out = new Array(items.length);
	let next = 0;
	async function worker() {
		while (true) {
			const i = next++;
			if (i >= items.length) return;
			out[i] = await fn(items[i], i);
		}
	}
	await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
	return out;
}

// --- Per-tool argument map ------------------------------------------------
function buildArgs(name, ctx = {}) {
	switch (name) {
		case 'batch_scan':
			return { domains: [TARGET] };
		case 'compare_domains':
			return { domains: [TARGET, 'example.com'] };
		case 'compare_baseline':
			return { domain: TARGET, baseline: { grade: 'B' } };
		case 'check_root_server_set':
		case 'get_benchmark':
		case 'list_brand_audit_watches':
			return {};
		case 'explain_finding':
			return { checkType: 'SPF', status: 'fail' };
		case 'get_provider_insights':
			return { provider: 'google workspace' };
		case 'validate_fix':
			return { domain: TARGET, check: 'dmarc' };
		case 'analyze_drift':
			return { domain: TARGET, baseline: 'cached' };
		case 'brand_audit_single':
			return { domain: TARGET, format: 'json' };
		case 'brand_audit_batch_start':
			return { domains: [TARGET], format: 'json' };
		case 'brand_audit_status':
			return { auditId: ctx.auditId ?? 'unknown' };
		case 'brand_audit_get_report':
			return { auditId: ctx.auditId ?? 'unknown' };
		case 'register_brand_audit_watch':
			return { domain: TARGET, interval: 'monthly' };
		case 'delete_brand_audit_watch':
			return { watchId: ctx.watchId ?? 'unknown' };
		default:
			return { domain: TARGET };
	}
}

// Fetch the deployed tool list via the MCP tools/list method.
async function listTools(session) {
	const res = await rpc(session, 'tools/list', {});
	if (res.error || !res.result || !Array.isArray(res.result.tools)) {
		throw new Error(`tools/list failed: ${res.error ?? 'no tools array'}`);
	}
	return res.result.tools.map((t) => t.name);
}

// --- Runner ---------------------------------------------------------------
async function runMatrix() {
	requireKey();
	const started = Date.now();
	const sessI = await createSession(REP_INTERACTIVE_UA);
	const sessN = await createSession(REP_NONINTERACTIVE_UA);
	const tools = await listTools(sessN);
	const sweep = tools.filter((t) => !MUTATING_TOOLS.has(t));

	const ctx = {};
	const setup = [];
	// Phase A — setup (non-interactive UA, so IDs are machine-readable).
	console.error('Phase A: setup (register watch, start audit)...');
	const reg = await callTool(sessN, 'register_brand_audit_watch', buildArgs('register_brand_audit_watch', ctx));
	ctx.watchId = reg.result ? extractId(reg.result, ['watchId', 'id']) : null;
	setup.push({ name: 'register_brand_audit_watch', env: checkEnvelope(reg), captured: ctx.watchId });
	const batch = await callTool(sessN, 'brand_audit_batch_start', buildArgs('brand_audit_batch_start', ctx));
	ctx.auditId = batch.result ? extractId(batch.result, ['auditId', 'id']) : null;
	setup.push({ name: 'brand_audit_batch_start', env: checkEnvelope(batch), captured: ctx.auditId });

	let toolResults = [];
	let clientResults = [];
	try {
		// Phase B — dual-session sweep.
		console.error(`Phase B: sweeping ${sweep.length} tools x 2 classes...`);
		toolResults = await mapConcurrent(sweep, CONCURRENCY, async (name) => {
			const args = buildArgs(name, ctx);
			const [ri, rn] = await Promise.all([callTool(sessI, name, args), callTool(sessN, name, args)]);
			return classifyTool({ name, ri, rn });
		});

		// Client axis — 9 other UAs each run check_spf.
		console.error('Phase B: client-axis wiring (check_spf x 9 UAs)...');
		const others = [
			...Object.entries(INTERACTIVE_UAS).filter(([k]) => k !== 'claude_code').map(([k, ua]) => [k, ua, 'interactive']),
			...Object.entries(NONINTERACTIVE_UAS).filter(([k]) => k !== 'mcp_remote').map(([k, ua]) => [k, ua, 'non-interactive']),
		];
		clientResults = await mapConcurrent(others, CONCURRENCY, async ([client, ua, expectedClass]) => {
			const session = await createSession(ua);
			const res = await callTool(session, 'check_spf', buildArgs('check_spf'));
			const env = checkEnvelope(res);
			const marker = res.result ? hasStructuredResult(res.result) : false;
			const expectMarker = expectedClass === 'non-interactive';
			const ok = env.ok && marker === expectMarker;
			return { client, ua, expectedClass, expectMarker, observedMarker: marker, env, ok };
		});
	} finally {
		// Phase C — teardown (best-effort even if Phase B threw).
		if (ctx.watchId) {
			console.error('Phase C: teardown (delete watch)...');
			const del = await callTool(sessN, 'delete_brand_audit_watch', { watchId: ctx.watchId });
			setup.push({ name: 'delete_brand_audit_watch', env: checkEnvelope(del), captured: ctx.watchId });
		}
	}

	return { tools, sweep, setup, toolResults, clientResults, ctx, durationMs: Date.now() - started };
}

// --- Reporting ------------------------------------------------------------
const GLYPH = { PASS: '✓', FAIL: '✗', INVARIANT: '~', RECORD: '·' };

function report(r) {
	console.log(`\n=== Client-Matrix Results — ${EP} (${(r.durationMs / 1000).toFixed(1)}s) ===\n`);

	console.log('Setup / teardown (mcp_remote):');
	for (const s of r.setup) {
		console.log(`  ${GLYPH[s.env.ok ? 'PASS' : 'FAIL']} ${s.name.padEnd(30)} ${s.env.ok ? 'ok' : s.env.reason}  id=${s.captured ?? '-'}`);
	}

	console.log('\nTool axis (interactive=claude_code vs non-interactive=mcp_remote):');
	const sorted = [...r.toolResults].sort((a, b) => a.name.localeCompare(b.name));
	for (const t of sorted) {
		console.log(`  ${GLYPH[t.status] ?? '?'} ${t.name.padEnd(34)} ${t.status}${t.reason ? ` — ${t.reason}` : ''}`);
	}

	console.log('\nClient axis (check_spf wiring):');
	for (const c of r.clientResults) {
		console.log(
			`  ${GLYPH[c.ok ? 'PASS' : 'FAIL']} ${c.client.padEnd(22)} ${c.expectedClass.padEnd(16)} marker expected=${c.expectMarker} observed=${c.observedMarker}${c.env.ok ? '' : ` [envelope: ${c.env.reason}]`}`,
		);
	}

	const toolFails = r.toolResults.filter((t) => t.status === 'FAIL');
	const setupFails = r.setup.filter((s) => !s.env.ok);
	const clientFails = r.clientResults.filter((c) => !c.ok);
	const counts = r.toolResults.reduce((m, t) => ((m[t.status] = (m[t.status] || 0) + 1), m), {});
	console.log(
		`\nSummary: tools ${JSON.stringify(counts)} | setup-fail ${setupFails.length} | client-fail ${clientFails.length} | total tools/call ≈ ${
			r.sweep.length * 2 + r.setup.length + r.clientResults.length
		}`,
	);

	const failed = toolFails.length + setupFails.length + clientFails.length;
	return failed === 0;
}

// --- Offline self-test of the pure helpers --------------------------------
function selfTest() {
	const full = {
		content: [{ type: 'text', text: '## SPF Check\nresult\n<!-- STRUCTURED_RESULT\n{"n":"abc123","score":80}\nSTRUCTURED_RESULT -->' }],
	};
	const compact = { content: [{ type: 'text', text: '## SPF Check\nresult' }] };
	const errEnvelope = { content: [{ type: 'text', text: 'boom' }], isError: true };
	// brand_audit_batch_start with format:'json' emits the id only as `auditId=<uuid>` (no JSON, no STRUCTURED_RESULT).
	const detailForm = { content: [{ type: 'text', text: '### Findings\n- Brand audit batch queued\n  auditId=2fe7d69b-1974-4d3d-9dcc-9a56a396e78c queuedAt=2026-05-24T11:58:25Z etaSeconds=180' }] };
	const cases = [
		['hasStructuredResult(full) === true', hasStructuredResult(full) === true],
		['hasStructuredResult(compact) === false', hasStructuredResult(compact) === false],
		["extractId(full, ['auditId','n']) === 'abc123'", extractId(full, ['auditId', 'n']) === 'abc123'],
		["extractId detail-form 'auditId=' captures id", extractId(detailForm, ['auditId', 'id']) === '2fe7d69b-1974-4d3d-9dcc-9a56a396e78c'],
		['checkEnvelope({result:full}).ok === true', checkEnvelope({ result: full }).ok === true],
		['checkEnvelope({result:errEnvelope}).ok === false', checkEnvelope({ result: errEnvelope }).ok === false],
		['checkEnvelope({error}).ok === false', checkEnvelope({ error: 'x', code: -32029 }).ok === false],
		['classify discriminated -> PASS', classifyTool({ name: 'check_spf', ri: { result: compact }, rn: { result: full } }).status === 'PASS'],
		['classify A-violation -> FAIL', classifyTool({ name: 'check_spf', ri: { result: full }, rn: { result: full } }).status === 'FAIL'],
		['classify no-marker -> INVARIANT', classifyTool({ name: 'generate_spf_record', ri: { result: compact }, rn: { result: compact } }).status === 'INVARIANT'],
		['record-only -> RECORD', classifyTool({ name: 'check_subdomain_takeover', ri: { result: errEnvelope }, rn: { result: errEnvelope } }).status === 'RECORD'],
	];
	let pass = 0;
	for (const [label, ok] of cases) {
		console.log(`${ok ? '✓' : '✗'} ${label}`);
		if (ok) pass++;
	}
	console.log(`\n${pass}/${cases.length} self-tests passed`);
	return pass === cases.length;
}

// --- Entrypoint -----------------------------------------------------------
if (SELF_TEST) {
	process.exit(selfTest() ? 0 : 1);
}

function requireKey() {
	if (!API_KEY) {
		console.error('Error: BV_API_KEY environment variable is required.');
		process.exit(1);
	}
}

async function dryRun() {
	requireKey();
	const session = await createSession(REP_NONINTERACTIVE_UA);
	const tools = await listTools(session);
	const sweep = tools.filter((t) => !MUTATING_TOOLS.has(t));
	console.log(`Endpoint: ${EP}`);
	console.log(`Target domain: ${TARGET}`);
	console.log(`Deployed tools: ${tools.length}`);
	console.log(`\nTool axis (run in BOTH claude_code + mcp_remote): ${sweep.length} tools`);
	for (const t of sweep) console.log(`  ${t.padEnd(34)} args=${JSON.stringify(buildArgs(t))}`);
	console.log(`\nSetup/teardown (mcp_remote only): ${[...MUTATING_TOOLS].join(', ')}`);
	console.log(`\nClient axis (check_spf): ${[...Object.keys(INTERACTIVE_UAS), ...Object.keys(NONINTERACTIVE_UAS)].join(', ')}`);
	// 3 setup/teardown calls (register, batch_start, delete) + 9 client-axis UAs (11 - 2 representatives).
	const SETUP_CALLS = 3;
	console.log(`\nEstimated tools/call count: ${sweep.length * 2 + SETUP_CALLS + (Object.keys(INTERACTIVE_UAS).length + Object.keys(NONINTERACTIVE_UAS).length - 2)}`);
}

if (DRY_RUN) {
	dryRun().then(() => process.exit(0)).catch((e) => {
		console.error(e.message);
		process.exit(1);
	});
}

if (!SELF_TEST && !DRY_RUN) {
	runMatrix()
		.then((r) => {
			const ok = report(r);
			if (JSON_OUT) {
				fs.writeFileSync(JSON_OUT, JSON.stringify(r, null, 2));
				console.error(`\nWrote structured results to ${JSON_OUT}`);
			}
			process.exit(ok ? 0 : 1);
		})
		.catch((e) => {
			console.error(e.stack || e.message);
			process.exit(1);
		});
}
