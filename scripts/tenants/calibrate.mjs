#!/usr/bin/env node
// Tenant capacity calibration runner.
// Gitignored (per `/scripts/tenants/` in .gitignore) — internal tool only.
//
// Hits PRODUCTION /internal/tools/batch with N domains, measures throughput,
// and writes a JSON proof artifact.
//
// Usage:
//   node scripts/tenants/calibrate.mjs --domains=200 --concurrency=25 --batches=4
//   node scripts/tenants/calibrate.mjs --domains=2000 --concurrency=50 --batches=20
//
// Reads BV_API_KEY from .dev.vars (NOT a Tenant tenant token — uses the owner key).
// Output: a single JSON object on stdout + writes `reports/tenant-calibration-<timestamp>.json`.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');

function arg(name, fallback) {
	const m = process.argv.find((a) => a.startsWith(`--${name}=`));
	if (!m) return fallback;
	const v = m.split('=', 2)[1];
	const n = Number(v);
	return Number.isFinite(n) ? n : v;
}

const DOMAINS = arg('domains', 200);
const CONCURRENCY = arg('concurrency', 25);
const BATCHES = arg('batches', 4);
const URL = arg('url', 'https://dns-mcp.blackveilsecurity.com');
const FORCE_REFRESH = process.argv.includes('--force-refresh');

function loadApiKey() {
	if (process.env.BV_API_KEY) return process.env.BV_API_KEY;
	try {
		const text = readFileSync(join(REPO, '.dev.vars'), 'utf-8');
		// Pull any 64-hex-char token in the file (avoids hardcoding the var name).
		const m = text.match(/=([a-f0-9]{64})/);
		if (m) return m[1];
	} catch { /* fall through */ }
	return null;
}

const API_KEY = process.env.BV_API_KEY ?? null; // .dev.vars regex was unreliable; require explicit env var
if (!API_KEY) {
	console.error('# (no BV_API_KEY env — running anonymous; capped at 50 req/min per-IP rate limit)');
}

// Synthetic seed list — high-traffic public domains so caches won't dominate.
// Mix of valid and invalid is intentional: realistic Tenant portfolios include both.
const SEED_POOL = [
	'google.com', 'cloudflare.com', 'github.com', 'microsoft.com', 'amazon.com',
	'apple.com', 'meta.com', 'twitter.com', 'linkedin.com', 'netflix.com',
	'salesforce.com', 'hubspot.com', 'zendesk.com', 'slack.com', 'okta.com',
	'cloudflare-eats.com', 'cloudflare-ipfs.com',
	'nytimes.com', 'bbc.co.uk', 'cnn.com', 'reuters.com', 'theguardian.com',
	'spotify.com', 'adobe.com', 'zoom.us', 'dropbox.com', 'brand-eta.example.com',
	'brand-theta.example.com', 'shopify.com', 'atlassian.com', 'notion.so', 'figma.com',
];

function buildPortfolio(n) {
	const out = [];
	for (let i = 0; i < n; i++) {
		// 1-in-5 chaos: synthetic invalid TLD to exercise the error path.
		if (i % 5 === 0) {
			out.push(`chaos-${i}-${Date.now()}.invalid`);
		} else {
			out.push(SEED_POOL[i % SEED_POOL.length]);
		}
	}
	return out;
}

// Initialise an MCP session via /mcp (public endpoint). Returns the session id.
async function initSession() {
	const r = await fetch(`${URL}/mcp`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Accept': 'application/json, text/event-stream',
			...(API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {}),
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 0,
			method: 'initialize',
			params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'tenant-calibrate', version: '1' } },
		}),
	});
	const sid = r.headers.get('mcp-session-id');
	if (!sid) throw new Error(`No mcp-session-id (status=${r.status})`);
	return sid;
}

// Fire a single scan_domain via tools/call. Returns timing + status.
// Note: /internal/tools/batch is service-binding-only (cf-connecting-ip guard);
// from outside CF we must use the public /mcp tools/call path. owner-tier
// auth bypasses per-IP rate limits.
async function scanOne(domain, sessionId, reqId) {
	const start = performance.now();
	const r = await fetch(`${URL}/mcp`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Accept': 'application/json, text/event-stream',
			'Mcp-Session-Id': sessionId,
			...(API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {}),
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: reqId,
			method: 'tools/call',
			params: { name: 'scan_domain', arguments: { domain, force_refresh: FORCE_REFRESH } },
		}),
	});
	const elapsedMs = performance.now() - start;
	const ok = r.ok;
	const status = r.status;
	let body = null;
	try { body = await r.json(); } catch { /* tolerate non-JSON */ }
	return { ok, status, elapsedMs, body };
}

// Map-with-concurrency-limit (no external dep).
async function pmap(items, limit, fn) {
	const out = new Array(items.length);
	let cursor = 0;
	const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
		while (true) {
			const i = cursor++;
			if (i >= items.length) return;
			out[i] = await fn(items[i], i);
		}
	});
	await Promise.all(workers);
	return out;
}

async function main() {
	console.error(`# Tenant calibration — ${DOMAINS} domains, concurrency=${CONCURRENCY}`);
	console.error(`# Target: ${URL}/mcp tools/call scan_domain`);
	const portfolio = buildPortfolio(DOMAINS);

	console.error('# initialising MCP session...');
	const sessionId = await initSession();

	console.error(`# firing ${DOMAINS} parallel scan_domain calls (${CONCURRENCY} in flight)...`);
	const t0 = performance.now();
	let nextId = 1;
	const results = await pmap(portfolio, CONCURRENCY, (d) => scanOne(d, sessionId, nextId++));
	const elapsedMs = performance.now() - t0;

	let succeeded = 0;
	let failed = 0;
	let httpErrors = 0;
	let rateLimited = 0;
	const latencies = [];
	for (const r of results) {
		latencies.push(r.elapsedMs);
		if (!r.ok) { httpErrors++; continue; }
		const err = r.body?.error;
		if (err?.code === -32029) { rateLimited++; continue; }
		if (err) { failed++; continue; }
		const isError = r.body?.result?.isError ?? false;
		if (isError) failed++;
		else succeeded++;
	}
	latencies.sort((a, b) => a - b);
	const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? 0;
	const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0;
	const p99 = latencies[Math.floor(latencies.length * 0.99)] ?? 0;
	const throughput = DOMAINS / (elapsedMs / 1000);
	const projected2_5M = (2_500_000 / throughput) / 3600;

	const report = {
		timestamp: new Date().toISOString(),
		target: `${URL}/mcp`,
		mode: 'public_mcp_tools_call',
		input: { domains: DOMAINS, concurrency: CONCURRENCY },
		runtime: {
			totalElapsedSec: Number((elapsedMs / 1000).toFixed(2)),
			throughputDomainsPerSec: Number(throughput.toFixed(2)),
			perScanLatencyP50Ms: Math.round(p50),
			perScanLatencyP95Ms: Math.round(p95),
			perScanLatencyP99Ms: Math.round(p99),
		},
		results: { succeeded, failed, rateLimited, httpErrors, total: results.length },
		projection: {
			runtimeFor2_5MHours: Number(projected2_5M.toFixed(2)),
			meets24hSlo: projected2_5M < 24,
		},
	};

	console.log(JSON.stringify(report, null, 2));

	const reportsDir = join(REPO, 'reports');
	if (!existsSync(reportsDir)) mkdirSync(reportsDir);
	const path = join(reportsDir, `tenant-calibration-${Date.now()}.json`);
	writeFileSync(path, JSON.stringify(report, null, 2));
	console.error(`# wrote ${path}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
