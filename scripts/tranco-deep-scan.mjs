#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
/**
 * Tranco Top-1000 Deep Scan
 *
 * Loads the base scan results, then runs every standalone analysis tool
 * on every domain — producing a comprehensive per-domain record with
 * output from all 29 analysis tools (16 from scan_domain + 13 standalone).
 *
 * Standalone tools run:
 *   check_lookalikes, check_shadow_domains, check_txt_hygiene,
 *   check_mx_reputation, check_srv, check_zone_hygiene,
 *   assess_spoofability, check_resolver_consistency,
 *   map_supply_chain, resolve_spf_chain, discover_subdomains,
 *   map_compliance, simulate_attack_paths
 *
 * Usage:
 *   node scripts/tranco-deep-scan.mjs [--base <scan.json>] [--concurrency N] [--out file.json]
 */

import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const EP = process.env.BV_MCP_ENDPOINT || 'https://dns-mcp.blackveilsecurity.com/mcp';
const API_KEY = process.env.BV_API_KEY;
if (!API_KEY) { console.error('Error: BV_API_KEY environment variable is required'); process.exit(1); }

const args = process.argv.slice(2);
const getArg = (flag, def) => {
	const i = args.indexOf(flag);
	return i !== -1 && args[i + 1] ? args[i + 1] : def;
};

// Find most recent base scan automatically
function findLatestBaseScan() {
	const dir = path.join('scripts');
	const files = fs.readdirSync(dir).filter((f) => f.startsWith('tranco-scan-') && f.endsWith('.json'));
	if (files.length === 0) throw new Error('No base scan found. Run tranco-scan.mjs first.');
	files.sort();
	return path.join(dir, files[files.length - 1]);
}

const BASE_FILE = getArg('--base', findLatestBaseScan());
const CONCURRENCY = parseInt(getArg('--concurrency', '25'), 10);
const TIMESTAMP = new Date().toISOString().slice(0, 16).replace('T', '_').replace(':', 'h') + 'm';
const OUTPUT = getArg('--out', path.join('scripts', `tranco-deep-${TIMESTAMP}.json`));

// Standalone tools that take only { domain }
const STANDALONE_TOOLS = [
	'check_txt_hygiene',
	'check_mx_reputation',
	'check_srv',
	'check_zone_hygiene',
	'assess_spoofability',
	'map_supply_chain',
	'resolve_spf_chain',
	'map_compliance',
	'simulate_attack_paths',
	'discover_subdomains',
	'check_resolver_consistency',
	'check_lookalikes',
	'check_shadow_domains',
];

const HEADERS = {
	'Content-Type': 'application/json',
	Accept: 'application/json',
	Authorization: `Bearer ${API_KEY}`,
	'User-Agent': 'bv-tranco-scan/1.0',
};

// ---------------------------------------------------------------------------
// MCP helpers
// ---------------------------------------------------------------------------
async function initSession() {
	const res = await fetch(EP, {
		method: 'POST',
		headers: HEADERS,
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: {
				protocolVersion: '2025-03-26',
				capabilities: {},
				clientInfo: { name: 'tranco-deep-scan', version: '1.0.0' },
			},
		}),
	});
	const sessionId = res.headers.get('mcp-session-id');
	if (!sessionId) throw new Error('No session ID returned from initialize');
	return sessionId;
}

async function callTool(toolName, domain, sessionId) {
	const res = await fetch(EP, {
		method: 'POST',
		headers: { ...HEADERS, 'Mcp-Session-Id': sessionId },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 2,
			method: 'tools/call',
			params: { name: toolName, arguments: { domain, format: 'compact' } },
		}),
		signal: AbortSignal.timeout(40_000),
	});
	const body = await res.json();
	if (body.error) return { _error: body.error.message ?? 'RPC error', _rateLimit: body.error.code === -32029 };

	const text = body.result?.content?.[0]?.text ?? '';
	// Try to extract structured result block
	const match = text.match(/<!--\s*STRUCTURED_RESULT\s+([\s\S]+?)\s*-->/);
	if (match) {
		try {
			return JSON.parse(match[1]);
		} catch {
			/* fall through to text */
		}
	}
	return { _text: text.slice(0, 2000) };
}

// ---------------------------------------------------------------------------
// Worker pool — processes (domain, tool) work items from a shared queue
// ---------------------------------------------------------------------------
async function runWorker(queue, sessions, workerIdx, results, progress) {
	const sessionId = sessions[workerIdx % sessions.length];

	while (queue.length > 0) {
		const item = queue.shift();
		if (!item) break;
		const { domain, tool } = item;

		let result;
		let attempt = 0;
		while (attempt < 2) {
			try {
				result = await callTool(tool, domain, sessionId);
				// Back off briefly on rate limit and don't retry
				if (result?._rateLimit) break;
				break;
			} catch (err) {
				attempt++;
				if (attempt >= 2) result = { _error: err.message ?? String(err) };
				else await new Promise((r) => setTimeout(r, 1000));
			}
		}

		if (!results[domain]) results[domain] = {};
		results[domain][tool] = result;

		progress.completed++;
		if (progress.completed % 250 === 0 || progress.completed === progress.total) {
			const elapsed = (Date.now() - progress.start) / 1000;
			const rate = progress.completed / elapsed;
			const eta = Math.round((progress.total - progress.completed) / rate);
			const pct = ((progress.completed / progress.total) * 100).toFixed(1);
			console.log(
				`  [${progress.completed}/${progress.total}] ${pct}%` +
					` — ${rate.toFixed(1)} calls/s — ETA ${eta}s`,
			);
		}
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
function printSummary(baseDomains, deepResults) {
	console.log('\n' + '═'.repeat(60));
	console.log('DEEP SCAN SUMMARY');
	console.log('═'.repeat(60));

	const total = baseDomains.length;
	const toolCalls = total * STANDALONE_TOOLS.length;
	const errors = Object.values(deepResults).flatMap((d) => Object.values(d)).filter((r) => r?._error).length;
	const rateLimited = Object.values(deepResults).flatMap((d) => Object.values(d)).filter((r) => r?._rateLimit).length;
	console.log(`Domains         : ${total}`);
	console.log(`Tool calls      : ${toolCalls}`);
	console.log(`Errors          : ${errors}`);
	console.log(`Rate limited    : ${rateLimited}`);

	// Spoofability distribution
	const spoofScores = Object.values(deepResults)
		.map((d) => d['assess_spoofability']?.spoofabilityScore ?? d['assess_spoofability']?.score)
		.filter((s) => typeof s === 'number');
	if (spoofScores.length > 0) {
		const avg = spoofScores.reduce((a, b) => a + b, 0) / spoofScores.length;
		spoofScores.sort((a, b) => a - b);
		console.log(`\nSpoofability score (0=safe, 100=trivially spoofable, N=${spoofScores.length})`);
		console.log(`  Mean   : ${avg.toFixed(1)}`);
		console.log(`  Median : ${spoofScores[Math.floor(spoofScores.length * 0.5)]}`);
		console.log(`  P75    : ${spoofScores[Math.floor(spoofScores.length * 0.75)]}`);
		const high = spoofScores.filter((s) => s >= 70).length;
		const med = spoofScores.filter((s) => s >= 40 && s < 70).length;
		const low = spoofScores.filter((s) => s < 40).length;
		console.log(`  High risk (≥70) : ${high} (${((high / spoofScores.length) * 100).toFixed(1)}%)`);
		console.log(`  Med  risk (40-69): ${med} (${((med / spoofScores.length) * 100).toFixed(1)}%)`);
		console.log(`  Low  risk (<40)  : ${low} (${((low / spoofScores.length) * 100).toFixed(1)}%)`);
	}

	// Supply chain — unique providers
	const allProviders = new Map();
	for (const d of Object.values(deepResults)) {
		const sc = d['map_supply_chain'];
		if (!sc || sc._error) continue;
		const providers = sc.providers ?? sc.outboundProviders ?? [];
		for (const p of providers) {
			const name = typeof p === 'string' ? p : p.name ?? p.provider;
			if (name) allProviders.set(name, (allProviders.get(name) ?? 0) + 1);
		}
	}
	if (allProviders.size > 0) {
		const top10 = [...allProviders.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
		console.log(`\nTop 10 supply-chain providers (by domain count):`);
		for (const [name, count] of top10) {
			const bar = '█'.repeat(Math.round((count / total) * 30));
			console.log(`  ${name.padEnd(30)} ${String(count).padStart(4)}  ${bar}`);
		}
	}

	// Compliance — pass rates per framework
	const complianceFrameworks = new Map();
	for (const d of Object.values(deepResults)) {
		const mc = d['map_compliance'];
		if (!mc || mc._error) continue;
		const frameworks = mc.frameworks ?? mc.controls ?? [];
		for (const fw of frameworks) {
			const name = fw.framework ?? fw.name;
			const pct = fw.passRate ?? fw.score ?? fw.percentage;
			if (name && typeof pct === 'number') {
				if (!complianceFrameworks.has(name)) complianceFrameworks.set(name, []);
				complianceFrameworks.get(name).push(pct);
			}
		}
	}
	if (complianceFrameworks.size > 0) {
		console.log(`\nCompliance framework pass rates (avg across domains):`);
		for (const [fw, scores] of complianceFrameworks) {
			const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
			console.log(`  ${fw.padEnd(30)} ${avg.toFixed(1)}%`);
		}
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
	console.log(`Tranco Top-1000 Deep Scan`);
	console.log(`Base scan : ${BASE_FILE}`);
	console.log(`Tools     : ${STANDALONE_TOOLS.join(', ')}`);
	console.log(`Concurrency: ${CONCURRENCY} sessions`);
	console.log(`Output    : ${OUTPUT}\n`);

	// Load base results for domain list
	const baseData = JSON.parse(fs.readFileSync(BASE_FILE, 'utf8'));
	const domains = baseData.map((r) => r.domain).filter(Boolean);
	console.log(`Loaded ${domains.length} domains from base scan\n`);

	// Build flat work queue: (domain, tool) pairs
	const queue = [];
	for (const domain of domains) {
		for (const tool of STANDALONE_TOOLS) {
			queue.push({ domain, tool });
		}
	}
	console.log(`Work queue: ${queue.length} tool calls (${domains.length} domains × ${STANDALONE_TOOLS.length} tools)\n`);

	// Initialise session pool
	console.log(`Initialising ${CONCURRENCY} sessions...`);
	const sessions = [];
	for (let i = 0; i < CONCURRENCY; i++) {
		sessions.push(await initSession());
		if (i < CONCURRENCY - 1) await new Promise((r) => setTimeout(r, 80));
	}
	console.log(`Sessions ready. Starting deep scan...\n`);

	const deepResults = {};
	const progress = { completed: 0, total: queue.length, start: Date.now() };

	await Promise.all(
		sessions.map((_, idx) => runWorker(queue, sessions, idx, deepResults, progress)),
	);

	const elapsed = ((Date.now() - progress.start) / 1000).toFixed(1);
	console.log(`\nDeep scan complete in ${elapsed}s`);

	// Merge base + deep results
	const merged = baseData.map((base) => ({
		...base,
		deep: deepResults[base.domain] ?? {},
	}));

	fs.writeFileSync(OUTPUT, JSON.stringify(merged, null, 2));
	console.log(`Merged results saved to ${OUTPUT}`);

	printSummary(domains, deepResults);
}

main().catch((err) => {
	console.error('Fatal:', err.message ?? err);
	process.exit(1);
});
