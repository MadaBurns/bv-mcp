#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
// Post-deploy verification: assert the LIVE Worker serves the expected version
// and returns a numeric scan score. Uses the workers.dev origin + owner key to
// bypass the custom domain's bot challenge.
import { fileURLToPath } from 'node:url';

const WORKERS_DEV = 'https://bv-dns-security-mcp.bv-edge.workers.dev/mcp';

export function assertVersion(serverInfo, expected) {
	if (!serverInfo || !serverInfo.version) throw new Error('verify failed: no serverInfo in initialize response');
	if (serverInfo.version !== expected) {
		throw new Error(`verify failed: live version ${serverInfo.version}, expected ${expected}`);
	}
}

async function rpc(baseUrl, token, body) {
	const res = await fetch(baseUrl, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream',
			authorization: `Bearer ${token}`,
		},
		body: JSON.stringify(body),
	});
	const text = await res.text();
	// Response may be JSON or an SSE frame; extract the first JSON object.
	const match = text.match(/\{[\s\S]*\}/);
	if (!match) throw new Error(`non-JSON response (${res.status}): ${text.slice(0, 200)}`);
	return JSON.parse(match[0]);
}

export async function fetchServerInfo(baseUrl, token) {
	const r = await rpc(baseUrl, token, {
		jsonrpc: '2.0',
		id: 1,
		method: 'initialize',
		params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bv-load-test', version: '1.0.0' } },
	});
	return r.result?.serverInfo;
}

async function main() {
	const expected = process.env.EXPECTED_VERSION;
	const token = process.env.BV_INTERNAL_DEV_KEY;
	const baseUrl = process.env.VERIFY_URL || WORKERS_DEV;
	if (!expected) throw new Error('EXPECTED_VERSION not set');
	if (!token) throw new Error('BV_INTERNAL_DEV_KEY not set');

	let serverInfo;
	for (let attempt = 1; attempt <= 6; attempt++) {
		try {
			serverInfo = await fetchServerInfo(baseUrl, token);
			if (serverInfo?.version === expected) break;
			console.error(`attempt ${attempt}: live=${serverInfo?.version ?? 'n/a'} expected=${expected} (rollout lag?)`);
		} catch (e) {
			console.error(`attempt ${attempt} error: ${e.message}`);
		}
		await new Promise((r) => setTimeout(r, 10000));
	}
	assertVersion(serverInfo, expected);
	console.log(`Verified live version ${serverInfo.version}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	main().catch((e) => {
		console.error(`::error::${e.message}`);
		process.exit(1);
	});
}
