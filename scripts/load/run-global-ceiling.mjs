#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const baseUrl = process.env.BV_LOAD_BASE_URL || 'https://dns-mcp.blackveilsecurity.com';
const lane = process.env.BV_LOAD_LANE || 'edge';
const duration = process.env.BV_LOAD_STAGE_DURATION || '5m';
const recoveryMs = Number(process.env.BV_LOAD_RECOVERY_MS || 120_000);
const rates = (process.env.BV_LOAD_RATES || '10,25,50,100,200,400,800,1600,3200').split(',').map(Number);
const evidenceDir = await mkdtemp(path.join(tmpdir(), 'bv-global-ceiling-'));
const records = [];

if (!rates.every((value) => Number.isInteger(value) && value > 0 && value <= 3200)) throw new Error('Invalid BV_LOAD_RATES');
if (lane !== 'edge' && !process.env.BV_LOAD_TEST_KEY) throw new Error('BV_LOAD_TEST_KEY is required outside the edge lane');
if (['useful', 'heavy', 'mixed'].includes(lane) && !process.env.BV_LOAD_DOMAIN) throw new Error('BV_LOAD_DOMAIN must be an explicitly approved BlackVeil-controlled domain');

function metric(summary, name, field) {
	return summary.metrics?.[name]?.values?.[field];
}

async function probe() {
	try {
		const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(5_000) });
		return response.ok && (await response.json()).status === 'ok';
	} catch {
		return false;
	}
}

async function runStage(rate) {
	const summaryPath = path.join(evidenceDir, `${lane}-${rate}.json`);
	const args = [
		'run', '--quiet',
		'--env', `BV_LOAD_BASE_URL=${baseUrl}`,
		'--env', `BV_LOAD_LANE=${lane}`,
		'--env', `BV_LOAD_RATE=${rate}`,
		'--env', `BV_LOAD_DURATION=${duration}`,
		'--env', `BV_LOAD_REGION=local`,
		'--env', `BV_LOAD_SUMMARY_PATH=${summaryPath}`,
		'scripts/load/global-ceiling.k6.js',
	];
	const child = spawn('k6', args, { stdio: 'inherit', env: process.env });
	let consecutiveProbeFailures = 0;
	const monitor = setInterval(async () => {
		if (await probe()) consecutiveProbeFailures = 0;
		else consecutiveProbeFailures += 1;
		if (consecutiveProbeFailures >= 2) child.kill('SIGINT');
	}, 10_000);
	const exitCode = await new Promise((resolve) => child.once('exit', resolve));
	clearInterval(monitor);
	const summary = JSON.parse(await readFile(summaryPath, 'utf8'));
	const record = {
		lane,
		rate,
		exitCode,
		requests: metric(summary, 'http_reqs', 'count'),
		failureRate: metric(summary, 'http_req_failed', 'rate'),
		semanticFailureRate: metric(summary, 'semantic_failures', 'rate'),
		schemaFailures: metric(summary, 'schema_failures', 'count') || 0,
		droppedIterations: metric(summary, 'dropped_iterations', 'count') || 0,
		p95LightMs: metric(summary, 'lightweight_latency', 'p(95)'),
		p99LightMs: metric(summary, 'lightweight_latency', 'p(99)'),
		maxLightMs: metric(summary, 'lightweight_latency', 'max'),
		p95HeavyMs: metric(summary, 'heavy_latency', 'p(95)'),
		p99HeavyMs: metric(summary, 'heavy_latency', 'p(99)'),
		maxHeavyMs: metric(summary, 'heavy_latency', 'max'),
		responseBytesP50: metric(summary, 'response_bytes', 'med'),
		responseBytesP95: metric(summary, 'response_bytes', 'p(95)'),
		responseBytesMax: metric(summary, 'response_bytes', 'max'),
		quotaResponses: metric(summary, 'quota_responses', 'count') || 0,
		wafResponses: metric(summary, 'waf_responses', 'count') || 0,
		probeAbort: consecutiveProbeFailures >= 2,
	};
	const latencyStable =
		lane === 'heavy'
			? (record.p95HeavyMs ?? Number.POSITIVE_INFINITY) <= 10_000
			: lane === 'mixed'
				? (record.p95LightMs ?? Number.POSITIVE_INFINITY) <= 500 && (record.p95HeavyMs ?? Number.POSITIVE_INFINITY) <= 10_000
				: (record.p95LightMs ?? Number.POSITIVE_INFINITY) <= 500;
	const semanticStable = lane === 'edge' || (record.semanticFailureRate ?? 1) <= 0.001;
	record.stable =
		exitCode === 0 &&
		!record.probeAbort &&
		record.droppedIterations === 0 &&
		record.schemaFailures === 0 &&
		(record.failureRate ?? 1) <= 0.001 &&
		semanticStable &&
		latencyStable;
	records.push(record);
	console.log(JSON.stringify(record));
	return record;
}

let consecutiveFailures = 0;
for (const rate of rates) {
	const record = await runStage(rate);
	consecutiveFailures = record.stable ? 0 : consecutiveFailures + 1;
	if (consecutiveFailures >= 2) break;
	if (rate !== rates.at(-1)) await new Promise((resolve) => setTimeout(resolve, recoveryMs));
}

const reportPath = path.join(evidenceDir, 'report.json');
await writeFile(reportPath, JSON.stringify({ generatedAt: new Date().toISOString(), baseUrl, lane, records }, null, 2));
console.log(`Evidence: ${reportPath}`);
process.exitCode = consecutiveFailures >= 2 ? 2 : 0;
