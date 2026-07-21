#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1
// Post-deploy verification: assert the LIVE Worker serves the expected version
// AND returns a sane scan_domain score (catches a stale dns-checks bundle
// where the version is right but scoring is broken). Uses the workers.dev
// origin + owner key to bypass the custom domain's bot challenge.
import { fileURLToPath } from 'node:url';

const WORKERS_DEV = 'https://bv-dns-security-mcp.bv-edge.workers.dev/mcp';
const SANITY_DOMAIN = 'blackveilsecurity.com';

export function assertVersion(serverInfo, expected) {
	if (!serverInfo || !serverInfo.version) throw new Error('verify failed: no serverInfo in initialize response');
	if (serverInfo.version !== expected) {
		throw new Error(`verify failed: live version ${serverInfo.version}, expected ${expected}`);
	}
}

/**
 * Pure guard for the post-deploy scan_domain sanity check: throws unless
 * structuredContent carries a finite numeric score. Returns the score on success.
 */
export function assertScoreSane(structuredContent) {
	if (!structuredContent) throw new Error('verify failed: no structuredContent in scan_domain response');
	const { score } = structuredContent;
	if (typeof score !== 'number' || !Number.isFinite(score)) {
		throw new Error(`verify failed: scan_domain score is not a finite number (got ${JSON.stringify(score)})`);
	}
	return score;
}

async function rpcWithHeaders(baseUrl, token, body, extraHeaders = {}) {
	const res = await fetch(baseUrl, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream',
			authorization: `Bearer ${token}`,
			...extraHeaders,
		},
		body: JSON.stringify(body),
	});
	const text = await res.text();
	// Response may be JSON or an SSE frame; extract the first JSON object.
	const match = text.match(/\{[\s\S]*\}/);
	if (!match) throw new Error(`non-JSON response (${res.status}): ${text.slice(0, 200)}`);
	return { json: JSON.parse(match[0]), headers: res.headers };
}

async function rpc(baseUrl, token, body, extraHeaders = {}) {
	const { json } = await rpcWithHeaders(baseUrl, token, body, extraHeaders);
	return json;
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

/**
 * Opens a session via `initialize` (capturing the `Mcp-Session-Id` response
 * header), then calls `scan_domain` against SANITY_DOMAIN with that session
 * and returns the parsed `structuredContent`.
 */
export async function fetchScanSanityStructuredContent(baseUrl, token, domain = SANITY_DOMAIN) {
	const { headers } = await rpcWithHeaders(baseUrl, token, {
		jsonrpc: '2.0',
		id: 1,
		method: 'initialize',
		params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bv-load-test', version: '1.0.0' } },
	});
	const sessionId = headers.get('mcp-session-id');
	if (!sessionId) throw new Error('verify failed: no Mcp-Session-Id header on initialize response');

	const { json } = await rpcWithHeaders(
		baseUrl,
		token,
		{
			jsonrpc: '2.0',
			id: 2,
			method: 'tools/call',
			params: { name: 'scan_domain', arguments: { domain, format: 'compact' } },
		},
		{ 'mcp-session-id': sessionId },
	);
	return json.result?.structuredContent;
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

	// Scan-sanity check: a stale dns-checks bundle can serve the right version
	// while scoring is broken. Retry a few times so a transient live-DNS
	// failure doesn't fail a good deploy, but a persistent broken bundle does.
	let score;
	let lastError;
	for (let attempt = 1; attempt <= 3; attempt++) {
		try {
			const structuredContent = await fetchScanSanityStructuredContent(baseUrl, token, SANITY_DOMAIN);
			score = assertScoreSane(structuredContent);
			lastError = undefined;
			break;
		} catch (e) {
			lastError = e;
			console.error(`scan-sanity attempt ${attempt} error: ${e.message}`);
			if (attempt < 3) await new Promise((r) => setTimeout(r, 10000));
		}
	}
	if (lastError) throw lastError;
	console.log(`Verified scan_domain sanity: ${SANITY_DOMAIN} score=${score}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	main().catch((e) => {
		console.error(`::error::${e.message}`);
		process.exit(1);
	});
}
