#!/usr/bin/env node
/**
 * Benchmark DoH resolver latency: Cloudflare (primary), bv-dns (secondary), Google (fallback).
 * Usage: node scripts/benchmark-doh.mjs [--rounds 20] [--bv-token TOKEN]
 */

const CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
const GOOGLE = 'https://dns.google/resolve';
const BV_DNS = 'https://secondary-doh.example.com/dns-query';

const TEST_QUERIES = [
	{ name: 'example.com', type: 'TXT' },
	{ name: 'google.com', type: 'MX' },
	{ name: 'cloudflare.com', type: 'A' },
	{ name: '_dmarc.github.com', type: 'TXT' },
	{ name: 'microsoft.com', type: 'NS' },
];

// Parse CLI args
const args = process.argv.slice(2);
let rounds = 20;
let bvToken = process.env.BV_DOH_TOKEN || '';
for (let i = 0; i < args.length; i++) {
	if (args[i] === '--rounds' && args[i + 1]) rounds = parseInt(args[i + 1], 10);
	if (args[i] === '--bv-token' && args[i + 1]) bvToken = args[i + 1];
}

function buildUrl(endpoint, name, type) {
	return `${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
}

async function queryResolver(endpoint, name, type, token) {
	const url = buildUrl(endpoint, name, type);
	const headers = { Accept: 'application/dns-json' };
	if (token) headers['X-BV-Token'] = token;

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 5000);
	const start = performance.now();

	try {
		const res = await fetch(url, { method: 'GET', headers, signal: controller.signal });
		const elapsed = performance.now() - start;
		if (!res.ok) return { elapsed, ok: false, status: res.status, answers: 0 };
		const data = await res.json();
		const answers = (data.Answer || []).length;
		return { elapsed, ok: true, status: res.status, answers };
	} catch (err) {
		const elapsed = performance.now() - start;
		return { elapsed, ok: false, status: 0, answers: 0, error: err.name === 'AbortError' ? 'timeout' : err.message };
	} finally {
		clearTimeout(timeout);
	}
}

function stats(values) {
	const sorted = [...values].sort((a, b) => a - b);
	const sum = sorted.reduce((a, b) => a + b, 0);
	return {
		min: sorted[0],
		p50: sorted[Math.floor(sorted.length * 0.5)],
		p95: sorted[Math.floor(sorted.length * 0.95)],
		max: sorted[sorted.length - 1],
		avg: sum / sorted.length,
	};
}

function fmt(ms) {
	return ms.toFixed(1).padStart(7) + 'ms';
}

async function main() {
	console.log(`DoH Resolver Benchmark — ${rounds} rounds × ${TEST_QUERIES.length} queries\n`);

	// Check bv-dns health first
	let bvDnsAvailable = false;
	try {
		const health = await fetch('https://secondary-doh.example.com/health', {
			signal: AbortSignal.timeout(3000),
		});
		bvDnsAvailable = health.ok;
		const body = await health.text();
		console.log(`bv-dns health: ${health.ok ? '✓ UP' : '✗ DOWN'} (${body.trim()})`);
	} catch (err) {
		console.log(`bv-dns health: ✗ UNREACHABLE (${err.message})`);
	}

	const resolvers = [
		{ name: 'Cloudflare', endpoint: CLOUDFLARE, token: undefined },
		...(bvDnsAvailable ? [{ name: 'bv-dns', endpoint: BV_DNS, token: bvToken || undefined }] : []),
		{ name: 'Google', endpoint: GOOGLE, token: undefined },
	];

	// Warm up (1 round, not counted)
	console.log('\nWarming up...');
	for (const r of resolvers) {
		for (const q of TEST_QUERIES) {
			await queryResolver(r.endpoint, q.name, q.type, r.token);
		}
	}

	// Benchmark
	const results = {};
	for (const r of resolvers) results[r.name] = { latencies: [], errors: 0, total: 0 };

	console.log(`Running ${rounds} rounds...\n`);

	for (let round = 0; round < rounds; round++) {
		for (const q of TEST_QUERIES) {
			// Query all resolvers in parallel for the same query
			const promises = resolvers.map(async (r) => {
				results[r.name].total++;
				const result = await queryResolver(r.endpoint, q.name, q.type, r.token);
				if (result.ok) {
					results[r.name].latencies.push(result.elapsed);
				} else {
					results[r.name].errors++;
				}
			});
			await Promise.all(promises);
		}
		if ((round + 1) % 5 === 0) process.stdout.write(`  ${round + 1}/${rounds}\n`);
	}

	// Results
	console.log('\n' + '═'.repeat(72));
	console.log(' Resolver Latency Comparison');
	console.log('═'.repeat(72));
	console.log(
		'Resolver'.padEnd(14) +
			'Min'.padStart(9) +
			'P50'.padStart(9) +
			'P95'.padStart(9) +
			'Max'.padStart(9) +
			'Avg'.padStart(9) +
			'  Err' +
			'  N',
	);
	console.log('─'.repeat(72));

	const resolverStats = {};
	for (const r of resolvers) {
		const d = results[r.name];
		if (d.latencies.length === 0) {
			console.log(`${r.name.padEnd(14)} — all ${d.total} queries failed`);
			continue;
		}
		const s = stats(d.latencies);
		resolverStats[r.name] = s;
		console.log(
			r.name.padEnd(14) +
				fmt(s.min) +
				fmt(s.p50) +
				fmt(s.p95) +
				fmt(s.max) +
				fmt(s.avg) +
				`  ${String(d.errors).padStart(3)}` +
				`  ${String(d.latencies.length).padStart(3)}`,
		);
	}
	console.log('─'.repeat(72));

	// Delta comparison
	if (resolverStats['Cloudflare'] && resolverStats['bv-dns']) {
		const cf = resolverStats['Cloudflare'];
		const bv = resolverStats['bv-dns'];
		const delta = bv.p50 - cf.p50;
		console.log(`\nbv-dns vs Cloudflare P50 delta: ${delta > 0 ? '+' : ''}${delta.toFixed(1)}ms`);
	}
	if (resolverStats['bv-dns'] && resolverStats['Google']) {
		const bv = resolverStats['bv-dns'];
		const g = resolverStats['Google'];
		const delta = bv.p50 - g.p50;
		console.log(`bv-dns vs Google P50 delta:     ${delta > 0 ? '+' : ''}${delta.toFixed(1)}ms`);
	}

	// Simulate secondary confirmation flow
	if (bvDnsAvailable) {
		console.log('\n' + '═'.repeat(72));
		console.log(' Secondary Confirmation Flow Simulation');
		console.log('═'.repeat(72));
		console.log('Simulates: Cloudflare empty → bv-dns → (if empty) → Google\n');

		const flowLatencies = { bvDnsHit: [], googleFallback: [] };

		for (let i = 0; i < Math.min(rounds, 10); i++) {
			for (const q of TEST_QUERIES) {
				// Simulate bv-dns hit (Cloudflare empty, bv-dns has answer)
				const start1 = performance.now();
				const bvResult = await queryResolver(BV_DNS, q.name, q.type, bvToken || undefined);
				if (bvResult.ok && bvResult.answers > 0) {
					flowLatencies.bvDnsHit.push(performance.now() - start1);
				}

				// Simulate full fallback chain (bv-dns empty → Google)
				const start2 = performance.now();
				await queryResolver(BV_DNS, `nonexistent-${i}.${q.name}`, q.type, bvToken || undefined);
				const gResult = await queryResolver(GOOGLE, `nonexistent-${i}.${q.name}`, q.type);
				flowLatencies.googleFallback.push(performance.now() - start2);
			}
		}

		if (flowLatencies.bvDnsHit.length > 0) {
			const s = stats(flowLatencies.bvDnsHit);
			console.log(`bv-dns hit (avoids Google):  P50 ${fmt(s.p50)}  P95 ${fmt(s.p95)}  Avg ${fmt(s.avg)}`);
		}
		if (flowLatencies.googleFallback.length > 0) {
			const s = stats(flowLatencies.googleFallback);
			console.log(`Full fallback (bv→Google):   P50 ${fmt(s.p50)}  P95 ${fmt(s.p95)}  Avg ${fmt(s.avg)}`);
		}
	}

	console.log('\nDone.');
}

main().catch(console.error);
