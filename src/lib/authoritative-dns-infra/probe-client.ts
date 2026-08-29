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
	const evidence = await readJsonResponse<DelegationConsistencyEvidence>(response, 'delegation consistency probe');
	// `analyzeDelegationConsistency` dereferences these arrays (and each glue entry's
	// parentIpv4/parentIpv6) unconditionally over this unchecked cast. Its sole caller,
	// checkNs, currently survives a malformed body only because its try happens to wrap
	// the analysis too — validate at the boundary so that fail-soft degrade is structural,
	// not an accident of try-scope (#828/#837 sibling). Empty arrays are legitimate
	// measurements here (e.g. `glue: []` = no in-bailiwick nameservers) and must pass.
	if (!isUsableDelegationEvidence(evidence)) {
		throw new Error('Invalid infra probe response: delegation consistency probe returned malformed evidence');
	}
	return evidence;
}

function isNamedObservationArray(value: unknown): boolean {
	return Array.isArray(value)
		&& value.every((entry) =>
			typeof entry === 'object'
			&& entry !== null
			&& typeof (entry as Record<string, unknown>).nameserver === 'string');
}

function isStringArray(value: unknown): boolean {
	return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function isUsableDelegationEvidence(evidence: DelegationConsistencyEvidence): boolean {
	return isStringArray(evidence.parentNameservers)
		&& isStringArray(evidence.parentDelegationNs)
		&& isNamedObservationArray(evidence.parentObservations)
		&& isNamedObservationArray(evidence.childObservations)
		&& isNamedObservationArray(evidence.glue)
		&& evidence.glue.every((entry) =>
			isStringArray((entry as unknown as Record<string, unknown>).parentIpv4)
			&& isStringArray((entry as unknown as Record<string, unknown>).parentIpv6));
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
	// The guard enforces the full typed contract (RootHintEntryEvidence: four required
	// strings) and non-emptiness: a body that merely fails this shape must never reach
	// `rootHintsMatchOfficial`, where it would score as a measured critical mismatch —
	// a scored claim manufactured from an unmeasured probe defect. A genuinely tampered
	// hint set is shape-valid with DIFFERENT values and still scores as a real failure.
	if (!isUsableRootHintArray(evidence.rootHints)) {
		throw new Error('Invalid infra probe response: root server set probe returned no usable rootHints');
	}
	return evidence;
}

function isUsableRootHintArray(rootHints: unknown): boolean {
	return Array.isArray(rootHints)
		&& rootHints.length > 0
		&& rootHints.every((hint) =>
			typeof hint === 'object'
			&& hint !== null
			&& typeof (hint as Record<string, unknown>).name === 'string'
			&& typeof (hint as Record<string, unknown>).ipv4 === 'string'
			&& typeof (hint as Record<string, unknown>).ipv6 === 'string'
			&& typeof (hint as Record<string, unknown>).operator === 'string');
}
