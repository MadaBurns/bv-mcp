// SPDX-License-Identifier: BUSL-1.1

/**
 * BANDAID agent-discovery posture check (IETF draft-mozleywilliams-dnsop-dnsaid).
 *
 * Assesses the *security posture* of DNS-published AI-agent discovery records —
 * complementary to dns-aid-core, which proves agent identity but only scores
 * svcb_valid / dnssec_valid / dane_valid / reachable. We focus on the surface
 * dns-aid leaves unscored: is the discovery zone DNSSEC-anchored (unsigned =
 * spoofable agent endpoints), and are declared capability documents
 * integrity-pinned (cap-sha256) and reachable.
 *
 * Standalone intelligence tool: out-of-union category, not scored, not in
 * scan_domain. Workers-compatible: DoH + safeFetch only.
 *
 * Caveat: draft-02 uses RFC 9460 Private-Use SVCB param code points
 * (65400–65409) pending IANA assignment — DNS_AID_PARAMS below is the single
 * place to update once IANA assigns official SvcParamKeys.
 */

import { queryDns } from '../lib/dns';
import { RecordType } from '../lib/dns-types';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory, Finding } from '../lib/scoring';
import { safeFetch } from '../lib/safe-fetch';

const CATEGORY = 'agent_discovery' as CheckCategory;

/** dns-aid custom SVCB param code points → friendly names (draft-02 §4). */
const DNS_AID_PARAMS: Record<string, string> = {
	key65400: 'cap',
	key65401: 'cap-sha256',
	key65402: 'bap',
	key65403: 'policy',
	key65404: 'realm',
	key65405: 'sig',
	key65406: 'connect-class',
	key65407: 'connect-meta',
	key65408: 'enroll-uri',
	key65409: 'well-known',
};

/** Per-fetch budget for capability-document integrity verification. */
const CAP_FETCH_TIMEOUT_MS = 5000;

/**
 * Max bytes read from a capability document. The `cap=` URL is attacker-
 * controlled (published in the scanned domain's DNS), so the body read is
 * bounded to prevent a malicious endpoint from exhausting worker memory.
 * Capability descriptors are small JSON documents — 256 KB is generous.
 */
const CAP_MAX_BYTES = 256 * 1024;

/**
 * Max number of capability documents fetched per call. The record count is
 * attacker-controlled (a domain can publish many SVCB records), so the
 * verify_cap fan-out is capped to prevent request amplification.
 */
const CAP_MAX_FETCHES = 10;

/**
 * Read a response body up to `maxBytes`, aborting early if the cap is exceeded.
 * Returns null when the body is too large — bounds memory on an
 * attacker-controlled endpoint that ignores/lacks Content-Length.
 */
async function readBounded(resp: Response, maxBytes: number): Promise<ArrayBuffer | null> {
	const reader = resp.body?.getReader();
	if (!reader) return null;
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		total += value.byteLength;
		if (total > maxBytes) {
			await reader.cancel();
			return null;
		}
		chunks.push(value);
	}
	const out = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.byteLength;
	}
	return out.buffer;
}

/** Agent communication protocols advertised in SVCB ALPN (dns-aid Protocol enum). */
export type AgentProtocol = 'a2a' | 'mcp' | 'https';

interface ParsedSvcb {
	owner: string;
	/** 0 = AliasMode, >0 = ServiceMode (RFC 9460). */
	priority: number;
	target: string;
	/** Params, friendly-named where known (cap, cap-sha256, …). */
	params: Record<string, string>;
}

/**
 * Parse one SVCB rdata presentation string from DoH `Answer.data`, e.g.
 * `1 chat.example.com. alpn="mcp" key65400="https://x/cap.json" key65401="aB.."`.
 * Our param values (URIs, base64/hex hashes) contain no spaces, so whitespace
 * tokenisation is safe; quoted values are unquoted.
 */
function parseSvcb(owner: string, data: string): ParsedSvcb | null {
	const tokens = data.trim().split(/\s+/);
	if (tokens.length < 2) return null;
	const priority = parseInt(tokens[0], 10);
	if (!Number.isFinite(priority)) return null;
	const target = tokens[1];
	const params: Record<string, string> = {};
	for (const tok of tokens.slice(2)) {
		const eq = tok.indexOf('=');
		if (eq < 0) {
			params[DNS_AID_PARAMS[tok] ?? tok] = '';
			continue;
		}
		const rawKey = tok.slice(0, eq);
		const rawVal = tok.slice(eq + 1).replace(/^"|"$/g, '');
		params[DNS_AID_PARAMS[rawKey] ?? rawKey] = rawVal;
	}
	return { owner, priority, target, params };
}

/** Candidate discovery owner-names per draft-02, narrowed by protocol/name. */
function discoveryNames(domain: string, protocol?: AgentProtocol, name?: string): string[] {
	if (name) {
		const names = [`${name}.${domain}`];
		if (protocol) names.push(`_${name}._${protocol}._agents.${domain}`); // legacy -01
		return names;
	}
	const names = [`_agents.${domain}`, `_index._agents.${domain}`];
	if (protocol) names.push(`_index._${protocol}._agents.${domain}`);
	return names;
}

/** Hex + base64 encodings of a SHA-256 digest, for flexible cap-sha256 compare. */
async function sha256Encodings(bytes: ArrayBuffer): Promise<{ hex: string; b64url: string }> {
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	const view = new Uint8Array(digest);
	const hex = Array.from(view, (b) => b.toString(16).padStart(2, '0')).join('');
	// dns-aid publishes cap-sha256 as base64url with padding stripped
	// (cap_fetcher.py: base64.urlsafe_b64encode(digest).rstrip(b'=')). Hex is
	// kept as a defensive fallback for non-canonical publishers.
	const b64url = btoa(String.fromCharCode(...view)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	return { hex, b64url };
}

/**
 * Fetch a declared capability document via safeFetch (attacker-controlled URL —
 * SSRF gate mandatory) and verify it against the cap-sha256 pin.
 */
async function verifyCapIntegrity(rec: ParsedSvcb, findings: Finding[]): Promise<void> {
	const capUri = rec.params['cap'];
	if (!capUri) return;

	const pin = rec.params['cap-sha256'];
	if (!pin) {
		findings.push(
			createFinding(
				CATEGORY,
				`Capability document not integrity-pinned (${rec.owner})`,
				'low',
				`Agent ${rec.owner} declares a capability document (cap=${capUri}) without a cap-sha256 hash. A network attacker who can alter the fetched document is not detectable.`,
				{ owner: rec.owner, capUri },
			),
		);
		return;
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), CAP_FETCH_TIMEOUT_MS);
	try {
		const resp = await safeFetch(capUri, { redirect: 'manual', signal: controller.signal });
		if (!resp.ok) {
			void resp.body?.cancel();
			findings.push(
				createFinding(
					CATEGORY,
					`Capability document unreachable (${rec.owner})`,
					'low',
					`cap=${capUri} declared by ${rec.owner} returned HTTP ${resp.status} — declared but not currently fetchable (descriptor_unreachable).`,
					{ owner: rec.owner, capUri, httpStatus: resp.status },
				),
			);
			return;
		}
		const body = await readBounded(resp, CAP_MAX_BYTES);
		if (body === null) {
			findings.push(
				createFinding(
					CATEGORY,
					`Capability document too large (${rec.owner})`,
					'low',
					`cap=${capUri} declared by ${rec.owner} exceeded the ${CAP_MAX_BYTES}-byte read cap — integrity not verified. A capability descriptor should be a small JSON document.`,
					{ owner: rec.owner, capUri, maxBytes: CAP_MAX_BYTES },
				),
			);
			return;
		}
		const { hex, b64url } = await sha256Encodings(body);
		const matches = pin === b64url || pin.toLowerCase() === hex.toLowerCase();
		findings.push(
			matches
				? createFinding(CATEGORY, `Capability document integrity verified (${rec.owner})`, 'info', `cap-sha256 of ${capUri} matches the published pin.`, {
						owner: rec.owner,
						capUri,
					})
				: createFinding(
						CATEGORY,
						`Capability document hash mismatch (${rec.owner})`,
						'high',
						`The fetched capability document at ${capUri} does NOT match the published cap-sha256 pin — the document was altered, replaced, or the pin is stale.`,
						{ owner: rec.owner, capUri, expected: pin, gotSha256Hex: hex },
					),
		);
	} catch (err) {
		findings.push(
			createFinding(
				CATEGORY,
				`Capability document unreachable (${rec.owner})`,
				'low',
				`cap=${capUri} declared by ${rec.owner} could not be fetched (${err instanceof Error ? err.message : 'fetch failed'}).`,
				{ owner: rec.owner, capUri },
			),
		);
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Check BANDAID agent-discovery posture for a domain.
 *
 * @param domain     Domain to inspect for published agent-discovery records.
 * @param options    Optional protocol-index scope, single-agent name, and
 *                   capability-document verification toggle.
 * @param dnsOptions DoH transport options threaded from the runtime.
 */
export async function checkAgentDiscovery(
	domain: string,
	options?: { protocol?: AgentProtocol; name?: string; verifyCap?: boolean },
	dnsOptions?: QueryDnsOptions,
): Promise<CheckResult> {
	const findings: Finding[] = [];
	const records: ParsedSvcb[] = [];
	const names = discoveryNames(domain, options?.protocol, options?.name);

	// Gather SVCB (type 64) records across candidate discovery names, querying
	// with the DNSSEC flag so we can read the AD (authenticated-data) signal
	// from the SAME response that carried the records — more robust than a
	// separate probe on a fixed name (which may sit across a zone cut).
	let dnssecAnchored = false;
	let anchorObserved = false;
	for (const owner of names) {
		let resp;
		try {
			resp = await queryDns(owner, 'SVCB', true, dnsOptions);
		} catch {
			continue; // NXDOMAIN / transient — try the next candidate
		}
		const answers = (resp.Answer ?? []).filter((a) => a.type === RecordType.SVCB);
		if (answers.length === 0) continue;
		if (!anchorObserved) {
			dnssecAnchored = resp.AD === true;
			anchorObserved = true;
		}
		for (const a of answers) {
			const parsed = parseSvcb(owner, a.data);
			if (parsed) records.push(parsed);
		}
	}

	// No discovery records at all — benign, informational.
	if (records.length === 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'No BANDAID agent-discovery records found',
				'info',
				`No SVCB agent-discovery records were published under the draft-02 names for ${domain} (${names.join(', ')}). The domain does not participate in DNS-based agent discovery.`,
				{ namesQueried: names },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// DNSSEC anchoring (dnssecAnchored) was captured above from the response
	// that carried the records. Unsigned discovery records are spoofable: an
	// on-path attacker can forge agent endpoints, and dns-aid's own validator
	// treats DANE/TLSA as untrustworthy without a validated chain (RFC 6698 §10.1).
	const serviceRecords = records.filter((r) => r.priority > 0);
	findings.push(
		createFinding(
			CATEGORY,
			`${serviceRecords.length} agent-discovery record(s) published`,
			'info',
			`${domain} publishes ${records.length} SVCB agent-discovery record(s) (${serviceRecords.length} ServiceMode), observed via draft-02 names: ${names.join(', ')}.`,
			{ recordCount: records.length, serviceModeCount: serviceRecords.length },
		),
	);

	if (!dnssecAnchored) {
		findings.push(
			createFinding(
				CATEGORY,
				'Agent-discovery records are not DNSSEC-anchored',
				'high',
				`Agent-discovery records for ${domain} were not returned with an authenticated-data (AD) DNSSEC signal. The advertised agent endpoints are spoofable by an on-path resolver, and any DANE/TLSA binding on them is untrustworthy (RFC 6698 §10.1). Sign the zone to make agent discovery verifiable.`,
				{ adFlag: false },
			),
		);
	} else {
		findings.push(
			createFinding(CATEGORY, 'Agent-discovery records are DNSSEC-anchored', 'info', `Discovery records for ${domain} are served under a DNSSEC-validated chain (AD flag set).`, {
				adFlag: true,
			}),
		);
	}

	// Capability-document integrity (declaration check always; fetch only on opt-in).
	if (options?.verifyCap) {
		// Cap the fan-out: the record count is attacker-controlled, so bound the
		// number of outbound cap-document fetches per call.
		const toFetch = serviceRecords.filter((r) => r.params['cap']);
		const capped = toFetch.slice(0, CAP_MAX_FETCHES);
		await Promise.all(capped.map((r) => verifyCapIntegrity(r, findings)));
		if (toFetch.length > CAP_MAX_FETCHES) {
			findings.push(
				createFinding(
					CATEGORY,
					'Capability verification truncated',
					'info',
					`${toFetch.length} agents declared a capability document; only the first ${CAP_MAX_FETCHES} were fetched and verified this call (amplification guard).`,
					{ declared: toFetch.length, verified: CAP_MAX_FETCHES },
				),
			);
		}
	} else {
		for (const r of serviceRecords) {
			if (r.params['cap'] && !r.params['cap-sha256']) {
				findings.push(
					createFinding(
						CATEGORY,
						`Capability document not integrity-pinned (${r.owner})`,
						'low',
						`Agent ${r.owner} declares cap=${r.params['cap']} without a cap-sha256 hash. Pass verify_cap=true to fetch and validate, or publish a cap-sha256 pin.`,
						{ owner: r.owner, capUri: r.params['cap'] },
					),
				);
			}
		}
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
