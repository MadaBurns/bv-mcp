// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Post-augments the package result with WAF-challenge awareness (issue #455): when
 * the policy-file fetch is intercepted by a Cloudflare/Akamai challenge or block
 * page (commonly HTTP 403), the package emits a confident `high`
 * "policy file not accessible"/"policy redirects" finding — a false positive on a
 * policy that real MTAs can fetch. We detect the interception from the policy
 * response (mirroring `check-http-security.ts`) and make the whole mta_sts category
 * INCONCLUSIVE — `checkStatus: 'error'` — so the scoring engine EXCLUDES it (neither
 * pass, fail, nor inflate) rather than penalising a healthy domain. The same excluded
 * shape is applied when the policy fetch THROWS (a WAF challenge that stalls past the
 * timeout → AbortError, or a network error), which the package would otherwise surface
 * as a confident `medium` "policy fetch failed".
 */

import { checkMTASTS } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { type WafEvent, looksLikeWaf, detectWafEvent, buildWafFinding } from '../lib/waf-detection';
import { readBoundedText } from '../lib/response-body';

/** Titles of the package's policy-fetch findings that a WAF interception can falsely trigger. */
const POLICY_FETCH_FALSE_POSITIVE_TITLES = new Set(['MTA-STS policy file not accessible', 'MTA-STS policy redirects']);

/**
 * The package's transient finding (emitted from its own catch path) when the policy
 * fetch THROWS. Empirically a `medium` finding with NO `checkStatus`/`partial` flag,
 * so scoring would penalise it — we exclude the category when this is present together
 * with an observed policy-fetch throw. (Title confirmed against the built package.)
 */
const POLICY_FETCH_THROW_TITLE = 'MTA-STS policy fetch failed';

/** True when this fetch is the MTA-STS policy-file fetch (the only thing fetchFn is used for). */
function isPolicyFetch(url: string): boolean {
	return url.includes('/.well-known/mta-sts.txt');
}

/**
 * Max bytes to read when fingerprinting a WAF page. The `mta-sts.<domain>` host
 * is controlled by the domain owner being scanned, so the policy-fetch body is
 * attacker-influenced. WAF challenge/block markers ("just a moment", "you have
 * been blocked") appear in the first bytes, so a small bounded read is sufficient
 * and prevents buffering a hostile multi-MB body.
 */
const MAX_WAF_SNIFF_BYTES = 8192;

/**
 * Best-effort, BOUNDED, BYTE-accurate body sniff for WAF fingerprinting. Clones so
 * the package's own handling of the original response (read or cancel) is undisturbed,
 * then delegates to the shared `readBoundedText` (byte-accurate cap, fail-open). Returns
 * '' if the body can't be read — detection must never throw.
 */
async function sniffBody(response: Response): Promise<string> {
	try {
		if (typeof response.clone !== 'function') return '';
		return await readBoundedText(response.clone().body, MAX_WAF_SNIFF_BYTES);
	} catch {
		return '';
	}
}

/**
 * Build the kind-aware inconclusive `info` finding for a WAF-intercepted policy fetch.
 * Provider is title-cased here; the title and detail wording branch on `event.kind`
 * (block vs challenge) — fixing the prior bug where the title hardcoded "challenge".
 */
function buildPolicyWafFinding(domain: string, event: WafEvent, status: number): Finding {
	const provider = event.provider.charAt(0).toUpperCase() + event.provider.slice(1);
	const isBlock = event.kind === 'block';
	const title = isBlock
		? `${provider} WAF blocked policy fetch — accessibility inconclusive`
		: `${provider} WAF challenge intercepted — policy accessibility inconclusive`;
	const interception = isBlock ? 'block' : 'challenge';
	const detail =
		`The MTA-STS policy fetch for https://mta-sts.${domain}/.well-known/mta-sts.txt was intercepted by a ${provider} ${interception} page (HTTP ${status}), not served by the origin. ` +
		`Real sending MTAs are not subject to the same interactive ${interception}, so the policy may well be reachable for mail delivery; its accessibility could not be verified externally by the scanner.`;
	return buildWafFinding('mta_sts', event, status, { title, detail });
}

/**
 * Replace the package's false-positive policy-fetch finding(s) with a single
 * inconclusive WAF `info` finding and EXCLUDE the category from scoring via
 * `checkStatus: 'error'` (mirrors check-http-security.ts). Other findings (the
 * TXT record presence, TLS-RPT, MX coverage) are kept for display — but the
 * `checkStatus: 'error'` still excludes the whole category from the score, so
 * a healthy domain is neither penalised nor inflated.
 */
function excludeForWaf(result: CheckResult, domain: string, event: WafEvent, status: number): CheckResult {
	const kept = result.findings.filter((f: Finding) => !POLICY_FETCH_FALSE_POSITIVE_TITLES.has(f.title));

	// Nothing to downgrade (e.g. the policy actually served fine on this run) — leave the result intact.
	if (kept.length === result.findings.length) return result;

	const inconclusive = buildPolicyWafFinding(domain, event, status);

	// controlPresent is preserved from the original result — the _mta-sts TXT record
	// was still observed; only the policy file fetch was inconclusive.
	return { ...buildCheckResult('mta_sts', [...kept, inconclusive], result.controlPresent), score: 0, passed: false, checkStatus: 'error' };
}

/**
 * The policy fetch THREW (WAF stall → AbortError, or a network error) and the package
 * surfaced its transient `medium` "policy fetch failed" finding. Drop that finding,
 * add an inconclusive WAF-style `info` note, and EXCLUDE the category — same shape as
 * a Response-based WAF event. Conservative: only invoked when we actually observed a
 * policy-fetch throw, so a genuine deterministic "not accessible" (a real 404 Response)
 * is untouched and keeps the package's `high`.
 */
function excludeForPolicyThrow(result: CheckResult, domain: string): CheckResult {
	const hasTransient = result.findings.some((f: Finding) => f.title === POLICY_FETCH_THROW_TITLE);
	// The package emitted something other than its transient throw finding — don't touch it.
	if (!hasTransient) return result;

	const kept = result.findings.filter((f: Finding) => f.title !== POLICY_FETCH_THROW_TITLE);
	// Unlike a Response-based WAF event, a throw carries NO provider evidence — do NOT
	// fabricate a `wafEvent` provider in the metadata (it would mislead analytics). Build a
	// plain inconclusive transient finding; `checkStatus: 'error'` below is what excludes the
	// category, not the finding metadata. `errorKind: 'timeout'` follows the repo's transient
	// convention (see lib/dns-error-result.ts).
	const inconclusive = createFinding(
		'mta_sts',
		'MTA-STS policy fetch stalled — accessibility inconclusive',
		'info',
		`The MTA-STS policy fetch for https://mta-sts.${domain}/.well-known/mta-sts.txt did not complete (the connection was aborted or stalled), ` +
			`consistent with a transient failure or a WAF challenge that real sending MTAs are not subject to. Policy accessibility could not be verified externally by the scanner.`,
		{ inconclusive: true, missingControl: true, errorKind: 'timeout' },
	);
	return { ...buildCheckResult('mta_sts', [...kept, inconclusive], result.controlPresent), score: 0, passed: false, checkStatus: 'error' };
}

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 */
export async function checkMtaSts(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	// Observe the policy-file fetch so a WAF challenge/block can be distinguished from a
	// genuine origin error. The wrapper only OBSERVES — it returns the original response
	// (or re-throws the original error) untouched so the package's behavior is unchanged;
	// we post-process its result below.
	//
	// Single-fetch contract: the package makes exactly ONE policy fetch matching
	// /.well-known/mta-sts.txt per call. We defensively capture only the FIRST observed
	// policy WAF event / throw and ignore any subsequent policy fetches, so a future
	// package change that retries can't overwrite or double-count the observation.
	let policyWafEvent: WafEvent | null = null;
	let policyWafStatus = 0;
	let policyFetchThrew = false;

	const observingFetch = async (url: string, init?: RequestInit): Promise<Response> => {
		const policy = isPolicyFetch(url);
		let response: Response;
		try {
			response = await fetch(url, init);
		} catch (err) {
			// A policy-fetch rejection (AbortError from a stalled WAF challenge, or a network
			// TypeError) is observed as inconclusive, then RE-THROWN so the package still runs
			// its own catch path and emits its transient finding. Only the FIRST policy throw
			// is recorded (single-fetch contract).
			if (policy && !policyFetchThrew && isObservableFetchThrow(err)) {
				policyFetchThrew = true;
			}
			throw err;
		}
		// Observation must be completely invisible to the package: any error here
		// (or a minimal Response without `headers`) must NOT alter the response the
		// package sees, or it would convert a real failure into a different finding.
		try {
			// Gate the body sniff to only run when detectWafEvent could actually fire — a
			// non-WAF sub-400 redirect or plain origin 404 (where cf-ray rides every Cloudflare
			// egress) must skip the clone+read entirely. Capture only the first policy event.
			if (
				policy &&
				!policyWafEvent &&
				!response.ok &&
				response.headers &&
				(response.status >= 400 || response.headers.get('cf-mitigated')) &&
				looksLikeWaf(response.headers)
			) {
				const body = await sniffBody(response);
				const event = detectWafEvent(response.headers, body, response.status);
				if (event) {
					policyWafEvent = event;
					policyWafStatus = response.status;
				}
			}
		} catch {
			// fail-open — leave policyWafEvent null so the package's own finding stands.
		}
		return response;
	};

	const result = (await checkMTASTS(domain, makeQueryDNS(dnsOptions), {
		timeout: dnsOptions?.timeoutMs ?? HTTPS_TIMEOUT_MS,
		fetchFn: observingFetch,
	})) as CheckResult;

	if (policyWafEvent) return excludeForWaf(result, domain, policyWafEvent, policyWafStatus);
	if (policyFetchThrew) return excludeForPolicyThrow(result, domain);
	return result;
}

/**
 * Only treat a policy-fetch rejection as inconclusive when it looks like a stall /
 * network failure (AbortError from the package's AbortSignal.timeout, or a TypeError
 * network error). Anything else is re-thrown unobserved so the package owns it.
 */
function isObservableFetchThrow(err: unknown): boolean {
	if (err instanceof Error) {
		return err.name === 'AbortError' || err.name === 'TimeoutError' || err instanceof TypeError;
	}
	return false;
}
