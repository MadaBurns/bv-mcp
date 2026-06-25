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
 * response (mirroring `check-http-security.ts`) and downgrade that finding to an
 * inconclusive `info`, recomputing the score so a healthy domain is not penalised.
 */

import { checkMTASTS } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { type WafEvent, looksLikeWaf, detectWafEvent } from '../lib/waf-detection';

/** Titles of the package's policy-fetch findings that a WAF interception can falsely trigger. */
const POLICY_FETCH_FALSE_POSITIVE_TITLES = new Set(['MTA-STS policy file not accessible', 'MTA-STS policy redirects']);

/** True when this fetch is the MTA-STS policy-file fetch (the only thing fetchFn is used for). */
function isPolicyFetch(url: string): boolean {
	return url.includes('/.well-known/mta-sts.txt');
}

/**
 * Max bytes to read when fingerprinting a WAF page. The `mta-sts.<domain>` host
 * is controlled by the domain owner being scanned, so the policy-fetch body is
 * attacker-influenced — and because Cloudflare's Worker egress injects `cf-ray`
 * onto EVERY response, `looksLikeWaf` is true for every non-ok policy fetch in
 * production, so this sniff runs on every 4xx/5xx. WAF challenge/block markers
 * ("just a moment", "you have been blocked") appear in the first bytes, so a
 * small bounded read is sufficient and prevents buffering a hostile multi-MB body.
 */
const MAX_WAF_SNIFF_BYTES = 8192;

/**
 * Best-effort, BOUNDED body sniff for WAF fingerprinting. Clones so the package's
 * own handling of the original response (read or cancel) is undisturbed; reads at
 * most MAX_WAF_SNIFF_BYTES then cancels the stream; returns '' if the body can't
 * be read (fail-open — detection must never throw).
 */
async function sniffBody(response: Response): Promise<string> {
	try {
		if (typeof response.clone !== 'function') return '';
		const body = response.clone().body;
		if (!body) return '';
		const reader = body.getReader();
		const decoder = new TextDecoder();
		let text = '';
		try {
			while (text.length < MAX_WAF_SNIFF_BYTES) {
				const { done, value } = await reader.read();
				if (done) break;
				text += decoder.decode(value, { stream: true });
			}
		} finally {
			// Stop buffering attacker-controlled data and release the stream.
			void reader.cancel().catch(() => {});
		}
		return text;
	} catch {
		return '';
	}
}

/**
 * Replace the package's false-positive policy-fetch finding(s) with a single
 * inconclusive `info` finding and recompute the score. Other findings (the TXT
 * record presence, TLS-RPT, MX coverage) are preserved — only the unverifiable
 * policy-accessibility claim is downgraded.
 */
function downgradeForWaf(result: CheckResult, domain: string, event: WafEvent, status: number): CheckResult {
	const provider = event.provider.charAt(0).toUpperCase() + event.provider.slice(1);
	const kept = result.findings.filter((f: Finding) => !POLICY_FETCH_FALSE_POSITIVE_TITLES.has(f.title));

	// Nothing to downgrade (e.g. the policy actually served fine on this run) — leave the result intact.
	if (kept.length === result.findings.length) return result;

	const inconclusive = createFinding(
		'mta_sts',
		`${provider} WAF challenge intercepted — policy accessibility inconclusive`,
		'info',
		`The MTA-STS policy fetch for https://mta-sts.${domain}/.well-known/mta-sts.txt was intercepted by a ${provider} ${event.kind} page (HTTP ${status}), not served by the origin. ` +
			`Real sending MTAs are not subject to the same interactive challenge, so the policy may well be reachable for mail delivery; its accessibility could not be verified externally by the scanner.`,
		{
			wafEvent: event.provider,
			wafKind: event.kind,
			// Back-compat with http_security: challenges carry `wafChallenge` with the provider name.
			...(event.kind === 'challenge' ? { wafChallenge: event.provider } : {}),
			httpStatus: status,
			inconclusive: true,
		},
	);

	// controlPresent is preserved from the original result — the _mta-sts TXT record
	// was still observed; only the policy file fetch was inconclusive.
	return buildCheckResult('mta_sts', [...kept, inconclusive], result.controlPresent);
}

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 */
export async function checkMtaSts(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	// Observe the policy-file fetch so a WAF challenge/block can be distinguished from a
	// genuine origin error. The wrapper only OBSERVES — it returns the original response
	// untouched so the package's behavior is unchanged; we post-process its result below.
	let policyWafEvent: WafEvent | null = null;
	let policyWafStatus = 0;

	const observingFetch = async (url: string, init?: RequestInit): Promise<Response> => {
		const response = await fetch(url, init);
		// Observation must be completely invisible to the package: any error here
		// (or a minimal Response without `headers`) must NOT alter the response the
		// package sees, or it would convert a real failure into a different finding.
		try {
			if (isPolicyFetch(url) && !response.ok && response.headers && looksLikeWaf(response.headers)) {
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

	if (policyWafEvent) return downgradeForWaf(result, domain, policyWafEvent, policyWafStatus);
	return result;
}
