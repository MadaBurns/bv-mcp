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
const MUTATING_TOOLS = new Set(['register_brand_audit_watch', 'brand_audit_batch_start', 'delete_brand_audit_watch']);
// `format` arg is output-mode (json|markdown|both), not verbosity — skip Invariant B.
const FORMAT_SPECIAL = new Set(['brand_audit_single', 'brand_audit_batch_start']);
// Envelope may legitimately be isError (not-ready / scan-only) — record, don't fail.
const RECORD_ONLY = new Set(['check_subdomain_takeover', 'brand_audit_get_report']);

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
		const m = text.match(new RegExp(`"${k}"\\s*:\\s*"([^"]+)"`));
		if (m) return m[1];
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

// --- Offline self-test of the pure helpers --------------------------------
function selfTest() {
	const full = {
		content: [{ type: 'text', text: '## SPF Check\nresult\n<!-- STRUCTURED_RESULT\n{"n":"abc123","score":80}\nSTRUCTURED_RESULT -->' }],
	};
	const compact = { content: [{ type: 'text', text: '## SPF Check\nresult' }] };
	const errEnvelope = { content: [{ type: 'text', text: 'boom' }], isError: true };
	const cases = [
		['hasStructuredResult(full) === true', hasStructuredResult(full) === true],
		['hasStructuredResult(compact) === false', hasStructuredResult(compact) === false],
		["extractId(full, ['auditId','n']) === 'abc123'", extractId(full, ['auditId', 'n']) === 'abc123'],
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
