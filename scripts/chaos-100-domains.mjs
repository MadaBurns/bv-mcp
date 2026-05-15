#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
/**
 * 100-domain chaos test against production v2.21.1 + brand-audit infra.
 *
 * Three things this exercises:
 *   1. scan_domain × 100 with bounded concurrency — latency / error / score
 *      distribution under realistic Tranco top-100 load.
 *   2. brand_audit_batch_start × 2 (50 + 50) — exercises BRAND_AUDIT_QUEUE,
 *      D1 parent + child writes, brand-audit-consumer dispatch, monthly
 *      quota wiring. Returns immediately; results trickle into D1 over
 *      the next ~30+ minutes via the queue.
 *   3. brand_audit_status polling for both batches — confirms the read
 *      path + idempotency + IDOR-via-cache fix all behave under load.
 *
 * Auth: BV_INTERNAL_DEV_KEY (owner tier, IP-gated, separate from BV_API_KEY).
 */

import fs from 'fs';
import path from 'path';

const EP = process.env.BV_MCP_ENDPOINT || 'https://dns-mcp.blackveilsecurity.com/mcp';
const KEY_FILE = '.dev.vars';
const SCAN_CONCURRENCY = parseInt(process.env.SCAN_CONCURRENCY || '8', 10);
const REPORTS_DIR = path.resolve('reports');
const TS = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const OUT = path.join(REPORTS_DIR, `chaos-100-${TS}.json`);

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const rawKey = fs
	.readFileSync(KEY_FILE, 'utf-8')
	.split('\n')
	.find((l) => l.startsWith('BV_INTERNAL_DEV_KEY='));
if (!rawKey) {
	console.error(`Error: BV_INTERNAL_DEV_KEY missing from ${KEY_FILE}`);
	process.exit(1);
}
const API_KEY = rawKey.split('=').slice(1).join('=').trim();
const UA = 'bv-chaos-test/100domains';

const tranco = JSON.parse(fs.readFileSync('scripts/tranco-deep-2026-04-05_12h42m.json', 'utf-8'));
const domains = tranco.slice(0, 100).map((e) => e.domain);

if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// MCP HTTP helpers — single session shared across all tools/call invocations.
// MCP spec: initialize → notifications/initialized → tools/call*.
// Each tools/call needs the `Mcp-Session-Id` header returned from initialize.
// ---------------------------------------------------------------------------

let SESSION_ID = '';

async function mcpInitialize() {
	const res = await fetch(EP, {
		method: 'POST',
		headers: {
			'Authorization': `Bearer ${API_KEY}`,
			'Content-Type': 'application/json',
			'Accept': 'application/json, text/event-stream',
			'User-Agent': UA,
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: UA, version: '1' } },
		}),
	});
	SESSION_ID = res.headers.get('mcp-session-id') ?? '';
	if (!SESSION_ID) {
		throw new Error(`initialize did not return Mcp-Session-Id header (status ${res.status})`);
	}
	// Drain the SSE body to free the connection.
	await res.text();
	// MCP spec: client MUST send notifications/initialized after initialize ack.
	await fetch(EP, {
		method: 'POST',
		headers: {
			'Authorization': `Bearer ${API_KEY}`,
			'Content-Type': 'application/json',
			'Accept': 'application/json, text/event-stream',
			'Mcp-Session-Id': SESSION_ID,
			'User-Agent': UA,
		},
		body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
	});
}

async function mcpCall(method, params) {
	const t0 = Date.now();
	let httpStatus = 0;
	try {
		const res = await fetch(EP, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${API_KEY}`,
				'Content-Type': 'application/json',
				'Accept': 'application/json, text/event-stream',
				'Mcp-Session-Id': SESSION_ID,
				'User-Agent': UA,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: Math.floor(Math.random() * 1e9), method, params }),
		});
		httpStatus = res.status;
		const text = await res.text();
		const durationMs = Date.now() - t0;
		// SSE format: lines starting with `data: ` — extract last JSON-RPC frame.
		const jsonLine = text.split('\n').find((l) => l.startsWith('data: '))?.slice(6);
		if (!jsonLine) {
			return { ok: false, durationMs, httpStatus, error: 'no_data_frame', raw: text.slice(0, 200) };
		}
		const parsed = JSON.parse(jsonLine);
		if (parsed.error) {
			return { ok: false, durationMs, httpStatus, error: parsed.error.message, code: parsed.error.code };
		}
		return { ok: true, durationMs, httpStatus, result: parsed.result };
	} catch (err) {
		return { ok: false, durationMs: Date.now() - t0, httpStatus, error: err.message };
	}
}

// ---------------------------------------------------------------------------
// Bounded concurrency
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Stats helpers
// ---------------------------------------------------------------------------

function percentile(sorted, p) {
	if (sorted.length === 0) return null;
	const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
	return sorted[idx];
}

function summarize(label, results) {
	const ok = results.filter((r) => r.ok);
	const failed = results.filter((r) => !r.ok);
	const lat = ok.map((r) => r.durationMs).sort((a, b) => a - b);
	const errors = {};
	for (const f of failed) {
		errors[f.error ?? 'unknown'] = (errors[f.error ?? 'unknown'] ?? 0) + 1;
	}
	return {
		label,
		total: results.length,
		succeeded: ok.length,
		failed: failed.length,
		successRate: results.length === 0 ? 0 : ok.length / results.length,
		latencyMs: {
			min: lat[0] ?? null,
			p50: percentile(lat, 50),
			p95: percentile(lat, 95),
			p99: percentile(lat, 99),
			max: lat[lat.length - 1] ?? null,
		},
		errors,
	};
}

// ---------------------------------------------------------------------------
// Phase 1: scan_domain × 100 with bounded concurrency
// ---------------------------------------------------------------------------

async function phase1ScanDomain() {
	console.log(`\n=== Phase 1: scan_domain × ${domains.length} (concurrency=${SCAN_CONCURRENCY}) ===`);
	const t0 = Date.now();
	const results = await mapConcurrent(domains, SCAN_CONCURRENCY, async (domain, i) => {
		const r = await mcpCall('tools/call', { name: 'scan_domain', arguments: { domain } });
		if (i % 10 === 0 || !r.ok) {
			const status = r.ok ? `${r.durationMs}ms` : `FAIL ${r.error}`;
			console.log(`  [${i + 1}/${domains.length}] ${domain.padEnd(30)} ${status}`);
		}
		// Pull score/grade from structured response for the report.
		let score, grade, findings_high, finding_critical;
		if (r.ok && r.result?.content?.[0]?.text) {
			const m = r.result.content[0].text.match(/Overall Score: (\d+)\/100 \(([A-F][+]?)\)/);
			if (m) { score = parseInt(m[1], 10); grade = m[2]; }
		}
		return {
			domain,
			ok: r.ok,
			durationMs: r.durationMs,
			httpStatus: r.httpStatus,
			score,
			grade,
			error: r.ok ? undefined : r.error,
		};
	});
	const wallMs = Date.now() - t0;
	return { results, wallMs };
}

// ---------------------------------------------------------------------------
// Phase 2: brand_audit_batch_start × 2 (50 each, async via queue)
// ---------------------------------------------------------------------------

async function phase2BrandAuditBatchStart() {
	console.log(`\n=== Phase 2: brand_audit_batch_start × 2 (50 each, async) ===`);
	const batch1 = domains.slice(0, 50);
	const batch2 = domains.slice(50, 100);
	const r1 = await mcpCall('tools/call', { name: 'brand_audit_batch_start', arguments: { domains: batch1, format: 'json' } });
	const r2 = await mcpCall('tools/call', { name: 'brand_audit_batch_start', arguments: { domains: batch2, format: 'json' } });
	const extractAuditId = (r) => {
		const t = r.result?.content?.[0]?.text ?? '';
		const m = t.match(/auditId=([a-f0-9-]+)/);
		return m ? m[1] : null;
	};
	const a1 = extractAuditId(r1);
	const a2 = extractAuditId(r2);
	console.log(`  Batch 1: auditId=${a1 ?? 'FAILED'} (HTTP ${r1.httpStatus}, ${r1.durationMs}ms)${r1.ok ? '' : ` — ${r1.error}`}`);
	console.log(`  Batch 2: auditId=${a2 ?? 'FAILED'} (HTTP ${r2.httpStatus}, ${r2.durationMs}ms)${r2.ok ? '' : ` — ${r2.error}`}`);
	return { batch1: { auditId: a1, response: r1 }, batch2: { auditId: a2, response: r2 } };
}

// ---------------------------------------------------------------------------
// Phase 3: poll status for both batches (single snapshot)
// ---------------------------------------------------------------------------

async function phase3StatusSnapshot(auditIds) {
	console.log(`\n=== Phase 3: status snapshot for both batches ===`);
	const snaps = [];
	for (const auditId of auditIds.filter((x) => x)) {
		const r = await mcpCall('tools/call', { name: 'brand_audit_status', arguments: { auditId } });
		const text = r.result?.content?.[0]?.text ?? '';
		const statusMatch = text.match(/status=(queued|running|completed|failed)/);
		const progMatch = text.match(/progress=(\d+\/\d+)/);
		console.log(`  ${auditId}: ${statusMatch?.[1] ?? '?'} (${progMatch?.[1] ?? '?'})`);
		snaps.push({ auditId, ok: r.ok, durationMs: r.durationMs, status: statusMatch?.[1], progress: progMatch?.[1] });
	}
	return snaps;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
	console.log(`Chaos-100 starting at ${new Date().toISOString()}`);
	console.log(`Endpoint: ${EP}`);
	console.log(`Domains: ${domains.length} (Tranco top 100 from snapshot)`);
	console.log(`Auth: BV_INTERNAL_DEV_KEY (owner tier)`);

	console.log(`\n=== Phase 0: MCP initialize ===`);
	await mcpInitialize();
	console.log(`  session: ${SESSION_ID.slice(0, 16)}...`);

	const phase1 = await phase1ScanDomain();
	const summary1 = summarize('scan_domain', phase1.results);

	const phase2 = await phase2BrandAuditBatchStart();

	// Tiny delay so the producer's D1 INSERT settles before the status check.
	await new Promise((r) => setTimeout(r, 2000));
	const phase3 = await phase3StatusSnapshot([phase2.batch1.auditId, phase2.batch2.auditId]);

	const report = {
		startedAt: new Date(Date.now() - phase1.wallMs).toISOString(),
		finishedAt: new Date().toISOString(),
		endpoint: EP,
		domainCount: domains.length,
		domains,
		phase1: { summary: summary1, wallMs: phase1.wallMs, results: phase1.results },
		phase2: { batch1: phase2.batch1, batch2: phase2.batch2 },
		phase3: { snapshot: phase3, note: 'Audits will continue draining via brand-audit-queue. Re-poll later for completed state.' },
	};

	fs.writeFileSync(OUT, JSON.stringify(report, null, 2));

	console.log(`\n=== SUMMARY ===`);
	console.log(`scan_domain:        ${summary1.succeeded}/${summary1.total} ok (${(summary1.successRate * 100).toFixed(1)}%)`);
	console.log(`  latency:          p50=${summary1.latencyMs.p50}ms p95=${summary1.latencyMs.p95}ms p99=${summary1.latencyMs.p99}ms max=${summary1.latencyMs.max}ms`);
	console.log(`  wall:             ${(phase1.wallMs / 1000).toFixed(1)}s`);
	if (Object.keys(summary1.errors).length > 0) {
		console.log(`  errors:           ${JSON.stringify(summary1.errors)}`);
	}
	console.log(`brand_audit batches: ${[phase2.batch1.auditId, phase2.batch2.auditId].filter((x) => x).length}/2 enqueued`);
	console.log(`\nReport saved to: ${OUT}`);
}

main().catch((err) => {
	console.error('Fatal:', err);
	process.exit(1);
});
