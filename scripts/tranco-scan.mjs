#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
/**
 * Tranco Top-1000 Domain Security Scan
 *
 * Fetches the current Tranco list, initialises a pool of MCP sessions,
 * and scans every domain in parallel — writing results to a timestamped
 * JSON file and printing a summary to stdout.
 *
 * Usage:
 *   node scripts/tranco-scan.mjs [--limit N] [--concurrency N] [--out file.json]
 */

import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const EP = 'https://dns-mcp.blackveilsecurity.com/mcp';
const API_KEY = 'bv_f021e37eeb8616997d7544c4e43ddb7da36e47c601501a59baac429fd91a6a3d';

const args = process.argv.slice(2);
const getArg = (flag, def) => {
	const i = args.indexOf(flag);
	return i !== -1 && args[i + 1] ? args[i + 1] : def;
};

const LIMIT = parseInt(getArg('--limit', '1000'), 10);
const CONCURRENCY = parseInt(getArg('--concurrency', '20'), 10);
const TIMESTAMP = new Date().toISOString().slice(0, 16).replace('T', '_').replace(':', 'h') + 'm';
const OUTPUT = getArg('--out', path.join('scripts', `tranco-scan-${TIMESTAMP}.json`));

const HEADERS = {
	'Content-Type': 'application/json',
	Accept: 'application/json',
	Authorization: `Bearer ${API_KEY}`,
};

// ---------------------------------------------------------------------------
// Tranco
// ---------------------------------------------------------------------------
async function fetchTrancoTop(n) {
	process.stdout.write('Fetching Tranco list metadata... ');
	const metaRes = await fetch('https://tranco-list.eu/api/lists/date/latest');
	if (!metaRes.ok) throw new Error(`Tranco metadata fetch failed: ${metaRes.status}`);
	const meta = await metaRes.json();
	const listId = meta.list_id;
	console.log(`list ${listId}`);

	process.stdout.write(`Downloading top ${n} domains... `);
	const csvRes = await fetch(`https://tranco-list.eu/download/${listId}/${n}`);
	if (!csvRes.ok) throw new Error(`Tranco download failed: ${csvRes.status}`);
	const text = await csvRes.text();
	console.log('done');

	const domains = text
		.trim()
		.split('\n')
		.map((line) => line.split(',')[1]?.trim())
		.filter(Boolean)
		.slice(0, n);
	return domains;
}

// ---------------------------------------------------------------------------
// MCP session helpers
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
				clientInfo: { name: 'tranco-scan', version: '1.0.0' },
			},
		}),
	});
	const sessionId = res.headers.get('mcp-session-id');
	if (!sessionId) throw new Error('No session ID returned from initialize');
	return sessionId;
}

async function scanDomain(domain, sessionId) {
	const res = await fetch(EP, {
		method: 'POST',
		headers: { ...HEADERS, 'Mcp-Session-Id': sessionId },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 2,
			method: 'tools/call',
			params: { name: 'scan_domain', arguments: { domain, format: 'compact' } },
		}),
		signal: AbortSignal.timeout(35_000),
	});
	const body = await res.json();
	if (body.error) return { domain, error: body.error.message ?? 'RPC error' };

	const text = body.result?.content?.[0]?.text ?? '';
	const match = text.match(/<!--\s*STRUCTURED_RESULT\s+([\s\S]+?)\s*-->/);
	if (match) {
		try {
			return JSON.parse(match[1]);
		} catch {
			/* fall through */
		}
	}
	// Compact clients don't get structured block — parse score from text
	const scoreMatch = text.match(/Overall Score[:\s]+(\d+)/i);
	const gradeMatch = text.match(/Grade[:\s]+([A-F][+]?)/i);
	return {
		domain,
		score: scoreMatch ? parseInt(scoreMatch[1], 10) : null,
		grade: gradeMatch ? gradeMatch[1] : null,
		rawText: text.slice(0, 300),
	};
}

// ---------------------------------------------------------------------------
// Worker pool
// ---------------------------------------------------------------------------
async function runWorker(workerId, queue, sessionId, results, progress) {
	while (queue.length > 0) {
		const domain = queue.shift();
		if (!domain) break;
		let attempt = 0;
		let result;
		while (attempt < 2) {
			try {
				result = await scanDomain(domain, sessionId);
				break;
			} catch (err) {
				attempt++;
				if (attempt >= 2) result = { domain, error: err.message ?? String(err) };
			}
		}
		results.push(result);
		progress.completed++;
		if (progress.completed % 25 === 0 || progress.completed === progress.total) {
			const elapsed = (Date.now() - progress.start) / 1000;
			const rate = progress.completed / elapsed;
			const eta = Math.round((progress.total - progress.completed) / rate);
			const pct = ((progress.completed / progress.total) * 100).toFixed(1);
			console.log(
				`  [${progress.completed}/${progress.total}] ${pct}% ` +
					`— ${rate.toFixed(1)} domains/s — ETA ${eta}s`,
			);
		}
	}
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
function printSummary(results) {
	const ok = results.filter((r) => !r.error && r.score != null);
	const errors = results.filter((r) => r.error);

	console.log('\n' + '═'.repeat(60));
	console.log('TRANCO TOP-1000 SECURITY SCAN SUMMARY');
	console.log('═'.repeat(60));
	console.log(`Domains scanned : ${results.length}`);
	console.log(`Successful      : ${ok.length}`);
	console.log(`Errors          : ${errors.length}`);

	if (ok.length === 0) return;

	const avg = ok.reduce((s, r) => s + r.score, 0) / ok.length;
	const scores = ok.map((r) => r.score).sort((a, b) => a - b);
	const p50 = scores[Math.floor(scores.length * 0.5)];
	const p25 = scores[Math.floor(scores.length * 0.25)];
	const p75 = scores[Math.floor(scores.length * 0.75)];

	console.log(`\nScore statistics (N=${ok.length})`);
	console.log(`  Mean   : ${avg.toFixed(1)}`);
	console.log(`  Median : ${p50}`);
	console.log(`  P25/P75: ${p25} / ${p75}`);
	console.log(`  Min/Max: ${scores[0]} / ${scores[scores.length - 1]}`);

	const grades = {};
	for (const r of ok) grades[r.grade ?? 'F'] = (grades[r.grade ?? 'F'] ?? 0) + 1;
	const gradeOrder = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F'];
	console.log('\nGrade distribution:');
	for (const g of gradeOrder) {
		if (!grades[g]) continue;
		const bar = '█'.repeat(Math.round((grades[g] / ok.length) * 40));
		console.log(`  ${g.padEnd(3)} ${String(grades[g]).padStart(4)}  ${bar}`);
	}

	// Top 10 best
	const top10 = [...ok].sort((a, b) => b.score - a.score).slice(0, 10);
	console.log('\nTop 10 domains:');
	for (const r of top10) console.log(`  ${r.domain?.padEnd(40)} ${r.score}/100 (${r.grade})`);

	// Bottom 10
	const bottom10 = [...ok].sort((a, b) => a.score - b.score).slice(0, 10);
	console.log('\nBottom 10 domains:');
	for (const r of bottom10) console.log(`  ${r.domain?.padEnd(40)} ${r.score}/100 (${r.grade})`);

	if (errors.length > 0) {
		console.log(`\nFirst 5 errors:`);
		for (const r of errors.slice(0, 5)) console.log(`  ${r.domain}: ${r.error}`);
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
	console.log(`Tranco Top-${LIMIT} Security Scan`);
	console.log(`Endpoint    : ${EP}`);
	console.log(`Concurrency : ${CONCURRENCY} sessions`);
	console.log(`Output      : ${OUTPUT}\n`);

	const domains = await fetchTrancoTop(LIMIT);
	console.log(`Domains loaded: ${domains.length}\n`);

	// Initialise session pool (max 30/min session creation rate)
	console.log(`Initialising ${CONCURRENCY} sessions...`);
	const sessions = [];
	for (let i = 0; i < CONCURRENCY; i++) {
		sessions.push(await initSession());
		if (i < CONCURRENCY - 1) await new Promise((r) => setTimeout(r, 100)); // gentle ramp
	}
	console.log(`Sessions ready. Starting scan...\n`);

	const queue = [...domains];
	const results = [];
	const progress = { completed: 0, total: domains.length, start: Date.now() };

	await Promise.all(sessions.map((sid, i) => runWorker(i, queue, sid, results, progress)));

	const elapsed = ((Date.now() - progress.start) / 1000).toFixed(1);
	console.log(`\nScan complete in ${elapsed}s`);

	// Save raw results
	fs.writeFileSync(OUTPUT, JSON.stringify(results, null, 2));
	console.log(`Results saved to ${OUTPUT}`);

	printSummary(results);
}

main().catch((err) => {
	console.error('Fatal:', err.message ?? err);
	process.exit(1);
});
