// SPDX-License-Identifier: BUSL-1.1

import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../lib/authoritative-dns-infra/root-hints';
import { normalizeInfraHostname } from '../lib/authoritative-dns-infra/probe-client';
import type {
	AuthoritativeDnsInfraEvidence,
	RootServerSetEvidence,
} from '../lib/authoritative-dns-infra/types';

interface AuthoritativeProbeRequest {
	hostname?: unknown;
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

async function readJson(request: Request): Promise<unknown> {
	try {
		return await request.json();
	} catch {
		return {};
	}
}

function validHostname(value: string): boolean {
	return value.length > 0 && value.length <= 253 && !value.includes('/') && !value.includes('\\');
}

async function handleAuthoritativeDnsProbe(request: Request): Promise<Response> {
	if (request.method !== 'POST') {
		return jsonResponse({ error: 'method_not_allowed' }, 405);
	}

	const body = await readJson(request) as AuthoritativeProbeRequest;
	const rawHostname = typeof body.hostname === 'string' ? body.hostname : '';
	const hostname = normalizeInfraHostname(rawHostname);
	if (!validHostname(hostname)) {
		return jsonResponse({ error: 'invalid_hostname' }, 400);
	}

	const evidence: AuthoritativeDnsInfraEvidence = {
		hostname,
		checkedAt: new Date().toISOString(),
		reachability: {
			ipv4: { addresses: [] },
			ipv6: { addresses: [] },
		},
		errors: ['raw_authoritative_dns_probe_not_implemented'],
	};
	return jsonResponse(evidence);
}

function handleRootServerSetProbe(request: Request): Response {
	if (request.method !== 'POST') {
		return jsonResponse({ error: 'method_not_allowed' }, 405);
	}

	const evidence: RootServerSetEvidence = {
		hostname: '.',
		checkedAt: new Date().toISOString(),
		rootHints: [...ROOT_HINTS],
		observedRootServers: [...ROOT_SERVER_NAMES],
		parentChildDelegationMatches: true,
		glueMatchesHints: true,
		errors: ['raw_root_server_set_probe_not_implemented'],
	};
	return jsonResponse(evidence);
}

export default {
	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === '/health') {
			return jsonResponse({ ok: true, service: 'bv-infra-probe' });
		}
		if (url.pathname === '/probe/authoritative-dns') {
			return handleAuthoritativeDnsProbe(request);
		}
		if (url.pathname === '/probe/root-server-set') {
			return handleRootServerSetProbe(request);
		}
		return jsonResponse({ error: 'not_found' }, 404);
	},
};
