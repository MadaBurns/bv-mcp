// SPDX-License-Identifier: BUSL-1.1

import { probeDelegationConsistency, type DelegationProbeDependencies } from '../lib/authoritative-dns-infra/delegation-probe';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from '../lib/authoritative-dns-infra/root-hints';
import { normalizeInfraHostname } from '../lib/authoritative-dns-infra/probe-client';
import { readBoundedText } from '../lib/request-body';
import type {
	AuthoritativeDnsInfraEvidence,
	RootServerSetEvidence,
} from '../lib/authoritative-dns-infra/types';

interface AuthoritativeProbeRequest {
	hostname?: unknown;
}

const MAX_PROBE_BODY_BYTES = 1024;

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

async function readJson(request: Request): Promise<{ ok: true; value: unknown } | { ok: false; status: 400 | 413 }> {
	const body = await readBoundedText(request, MAX_PROBE_BODY_BYTES);
	if (!body.ok) return { ok: false, status: 413 };
	try {
		return { ok: true, value: JSON.parse(body.text) as unknown };
	} catch {
		return { ok: false, status: 400 };
	}
}

function validHostname(value: string): boolean {
	if (value.length === 0 || value.length > 253 || value.includes('/') || value.includes('\\')) return false;
	const labels = value.split('.');
	return labels.length >= 2 && labels.every(
		(label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
	);
}

function rootHintForHostname(hostname: string) {
	return ROOT_HINTS.find((hint) => hint.name === hostname);
}

async function handleAuthoritativeDnsProbe(request: Request): Promise<Response> {
	if (request.method !== 'POST') {
		return jsonResponse({ error: 'method_not_allowed' }, 405);
	}

	const parsed = await readJson(request);
	if (!parsed.ok) return jsonResponse({ error: parsed.status === 413 ? 'request_body_too_large' : 'invalid_json' }, parsed.status);
	const body = parsed.value as AuthoritativeProbeRequest;
	const rawHostname = typeof body.hostname === 'string' ? body.hostname : '';
	const hostname = normalizeInfraHostname(rawHostname);
	if (!validHostname(hostname)) {
		return jsonResponse({ error: 'invalid_hostname' }, 400);
	}

	const rootHint = rootHintForHostname(hostname);
	const evidence: AuthoritativeDnsInfraEvidence = {
		hostname,
		checkedAt: new Date().toISOString(),
		reachability: {
			ipv4: { addresses: rootHint ? [rootHint.ipv4] : [] },
			ipv6: { addresses: rootHint ? [rootHint.ipv6] : [] },
		},
		errors: ['live_raw_dns_probe_not_configured'],
	};

	if (rootHint) {
		evidence.rootPriming = {
			nsNames: [...ROOT_SERVER_NAMES],
			matchesOfficialHints: true,
		};
		evidence.transportParity = {
			ipv4Ipv6Parity: true,
			notes: [`official_root_hint_operator:${rootHint.operator}`],
		};
		evidence.operationalExposure = {
			ptrRecords: [hostname],
		};
	}

	return jsonResponse(evidence);
}

export async function handleDelegationConsistencyProbe(
	request: Request,
	dependencies: DelegationProbeDependencies = {},
): Promise<Response> {
	if (request.method !== 'POST') {
		return jsonResponse({ error: 'method_not_allowed' }, 405);
	}

	const parsed = await readJson(request);
	if (!parsed.ok) return jsonResponse({ error: parsed.status === 413 ? 'request_body_too_large' : 'invalid_json' }, parsed.status);
	const body = parsed.value as AuthoritativeProbeRequest;
	const rawHostname = typeof body.hostname === 'string' ? body.hostname : '';
	const hostname = normalizeInfraHostname(rawHostname);
	if (!validHostname(hostname)) {
		return jsonResponse({ error: 'invalid_hostname' }, 400);
	}

	try {
		return jsonResponse(await probeDelegationConsistency(hostname, dependencies));
	} catch {
		console.error('Delegation consistency probe failed');
		return jsonResponse({ error: 'delegation_probe_failed' }, 502);
	}
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
		errors: ['live_root_server_set_probe_not_configured'],
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
		if (url.pathname === '/probe/delegation-consistency') {
			return handleDelegationConsistencyProbe(request);
		}
		if (url.pathname === '/probe/root-server-set') {
			return handleRootServerSetProbe(request);
		}
		return jsonResponse({ error: 'not_found' }, 404);
	},
};
