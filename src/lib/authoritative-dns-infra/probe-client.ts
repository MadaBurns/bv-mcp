// SPDX-License-Identifier: BUSL-1.1

import type { DelegationConsistencyEvidence } from './delegation-types';
import type { AuthoritativeDnsInfraEvidence, RootServerSetEvidence } from './types';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../response-body';

const INFRA_PROBE_TIMEOUT_MS = 5_000;
const INFRA_PROBE_MAX_BODY_BYTES = 256 * 1024;

export interface InfraProbeBinding {
	fetch: typeof fetch;
}

export function normalizeInfraHostname(domain: string): string {
	return domain.trim().toLowerCase().replace(/\.$/, '');
}

async function readJsonResponse<T>(response: Response, probeName: string): Promise<T> {
	if (!response.ok) {
		await disposeUnreadResponseBody(response);
		throw new Error(`Invalid infra probe response: ${probeName} returned HTTP ${response.status}`);
	}
	const body = await readJsonResponseCapped<T>(response, INFRA_PROBE_MAX_BODY_BYTES);
	if (body === null) throw new Error(`Invalid infra probe response: ${probeName} returned malformed or oversized JSON`);
	return body;
}

export async function fetchAuthoritativeDnsEvidence(domain: string, infraProbe: InfraProbeBinding): Promise<AuthoritativeDnsInfraEvidence> {
	const response = await infraProbe.fetch('https://infra-probe.internal/probe/authoritative-dns', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ hostname: normalizeInfraHostname(domain) }),
		signal: AbortSignal.timeout(INFRA_PROBE_TIMEOUT_MS),
	});
	return readJsonResponse<AuthoritativeDnsInfraEvidence>(response, 'authoritative dns probe');
}

export async function fetchDelegationConsistencyEvidence(
	domain: string,
	infraProbe: InfraProbeBinding,
): Promise<DelegationConsistencyEvidence> {
	const response = await infraProbe.fetch('https://infra-probe.internal/probe/delegation-consistency', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ hostname: normalizeInfraHostname(domain) }),
		signal: AbortSignal.timeout(INFRA_PROBE_TIMEOUT_MS),
	});
	return readJsonResponse<DelegationConsistencyEvidence>(response, 'delegation consistency probe');
}

export async function fetchRootServerSetEvidence(infraProbe: InfraProbeBinding): Promise<RootServerSetEvidence> {
	const response = await infraProbe.fetch('https://infra-probe.internal/probe/root-server-set', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({}),
		signal: AbortSignal.timeout(INFRA_PROBE_TIMEOUT_MS),
	});
	const evidence = await readJsonResponse<RootServerSetEvidence>(response, 'root server set probe');
	// `rootHints` is the one field `analyzeRootServerSetEvidence` dereferences without a
	// guard (every other evidence field is optional-chained), and `readJsonResponse` is an
	// unchecked cast — so a malformed 200 body must be rejected HERE, where the caller's
	// existing try/catch degrades it to the probe-unavailable inconclusive path (#828).
	if (
		!Array.isArray(evidence.rootHints)
		|| evidence.rootHints.some((hint) => typeof hint !== 'object' || hint === null)
	) {
		throw new Error('Invalid infra probe response: root server set probe returned no usable rootHints');
	}
	return evidence;
}
