// SPDX-License-Identifier: BUSL-1.1

import type { AuthoritativeDnsInfraEvidence, RootServerSetEvidence } from './types';

export interface InfraProbeBinding {
	fetch: typeof fetch;
}

export function normalizeInfraHostname(domain: string): string {
	return domain.trim().toLowerCase().replace(/\.$/, '');
}

async function readJsonResponse<T>(response: Response, probeName: string): Promise<T> {
	if (!response.ok) {
		throw new Error(`Invalid infra probe response: ${probeName} returned HTTP ${response.status}`);
	}
	return response.json() as Promise<T>;
}

export async function fetchAuthoritativeDnsEvidence(
	domain: string,
	infraProbe: InfraProbeBinding,
): Promise<AuthoritativeDnsInfraEvidence> {
	const response = await infraProbe.fetch('https://infra-probe.internal/probe/authoritative-dns', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ hostname: normalizeInfraHostname(domain) }),
	});
	return readJsonResponse<AuthoritativeDnsInfraEvidence>(response, 'authoritative dns probe');
}

export async function fetchRootServerSetEvidence(
	infraProbe: InfraProbeBinding,
): Promise<RootServerSetEvidence> {
	const response = await infraProbe.fetch('https://infra-probe.internal/probe/root-server-set', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({}),
	});
	return readJsonResponse<RootServerSetEvidence>(response, 'root server set probe');
}
