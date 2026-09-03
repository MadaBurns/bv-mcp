// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Post-augments the package result with WAF-challenge awareness (issue #455): when
 * the policy-file fetch is intercepted by a Cloudflare/Akamai challenge or block
 * page (commonly HTTP 403), the package emits a confident `high`
 * "policy file not accessible"/"policy redirects" finding — a claim of fact derived
 * from a probe that never reached the origin. We detect the interception from the policy
 * response (mirroring `check-http-security.ts`) and make the whole mta_sts category
 * INCONCLUSIVE — `checkStatus: 'error'` — so the scoring engine EXCLUDES it (neither
 * pass, fail, nor inflate).
 *
 * A policy fetch that THROWS (a stall past the timeout → AbortError, a network error, a
 * robots.txt disallow, a budget cut per #674) is handled by the PACKAGE since dns-checks
 * 1.33.0 (issue #889): `checkMTASTS` itself returns the not-assessed shape (`checkStatus`
 * `'timeout' | 'error'`, score 0, `partial: true`, an `info` finding carrying
 * `notAssessedReason`) instead of the confident `medium` "policy fetch failed" it used to
 * score. This wrapper no longer has to strip a scored finding; what it still owns on that
 * path is (a) the WAF-aware prose of the inconclusive finding (#664) and (b) pinning the
 * status to `'error'` — the package classifies a stall as `'timeout'`, which is faithful
 * for direct package consumers but is NOT the class `scan_domain`'s transient-zero retry
 * fires on (`shouldRetry` deliberately excludes `'timeout'`, the safeCheck-killed shape).
 * See `excludeForPolicyThrow`.
 *
 * ⚠️ Exclusion is the whole remedy — the prose must not go on to reassure the reader that
 * real sending MTAs can fetch the policy anyway (issue #664). We have not measured that;
 * see the note on `buildPolicyWafFinding`.
 */

import { checkMTASTS, withRobotsGate, RobotsDisallowedError } from '@blackveil/dns-checks';
import type { FetchFunction, ZoneContext } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import { resolveZoneApex } from '../lib/zone-apex';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { type WafEvent, looksLikeWaf, detectWafEvent, buildWafFinding } from '../lib/waf-detection';
import { readBoundedText } from '../lib/response-body';
import { createFetchBudget, type FetchBudget } from '../lib/fetch-budget';

/**
 * Module-scope, isolate-lifetime gated fetch. Deliberately NOT per-call: this
 * file's real network call is inside `observingFetch`, a helper nested inside
 * `checkMtaSts` rather than itself the exported per-scan entry point, and
 * `withRobotsGate`'s per-hostname robots.txt memoization is only useful if the
 * wrapped fetch persists across calls (see the plan's Global Constraints).
 *
 * Wrapped as `(...args) => fetch(...args)` rather than passing the bare `fetch`
 * identifier: `withRobotsGate` captures whatever function VALUE it's given, and
 * `fetch` passed directly captures the global fetch binding AT MODULE-EVAL TIME
 * — permanently, since it's a value, not a live lookup. A bare `fetch(...)` CALL
 * inside a function body re-resolves the current `globalThis.fetch` on every
 * invocation, but a bare `fetch` reference handed to another function as an
 * argument does not carry that live-lookup behavior with it. Production
 * `globalThis.fetch` is never reassigned post-boot, so this is invisible there —
 * but this repo's tests reassign `globalThis.fetch` per-case (`setupFetchMock`),
 * and a captured-by-value `fetch` would keep calling whichever mock happened to
 * be installed the first time this module was evaluated, silently ignoring every
 * later test's mock. The indirection keeps the SAME module-scope cache lifetime
 * (this is still one `withRobotsGate` instance / one `groupCache`) while keeping
 * the innermost fetch call dynamic.
 */
const gatedFetch = withRobotsGate((url: string, init?: RequestInit) => fetch(url, init));

/**
 * Resolve the gated fetch for one invocation (issue #674).
 *
 * No budget (every direct `check_mta_sts` call, `validate_fix`, `generate_records`,
 * `simulate_attack_paths`, and every BSL self-host) → the module-scope `gatedFetch`
 * above, whose isolate-lifetime robots.txt cache is untouched. Byte-for-byte the
 * expression that shipped before this change.
 *
 * Budgeted (a `scan_domain` fan-out) → a fresh gate whose inner fetch is metered.
 * Budget INNERMOST, as in check-ssl/check-http-security: the gate fetches
 * `https://mta-sts.<domain>/robots.txt` (up to ROBOTS_FETCH_TIMEOUT_MS = 3s) BEFORE it
 * lets the policy fetch through, and that leg delegates down through the wrapped fetch
 * — so hoisting the budget outside the gate would leave the more expensive of the two
 * legs unmetered. The cost is a per-call gate (no cross-call robots memo) on the scan
 * path only; there is nothing to share it with anyway, since `mta-sts.<domain>` is a
 * different host from the one `ssl`/`http_security` probe (see the robotsMemo note in
 * scan-domain.ts).
 */
function resolveGatedFetch(budget: FetchBudget, budgeted: boolean): FetchFunction {
	if (!budgeted) return gatedFetch;
	return withRobotsGate(budget.wrap((url: string, init?: RequestInit) => fetch(url, init)));
}

/** Titles of the package's policy-fetch findings that a WAF interception can falsely trigger. */
const POLICY_FETCH_FALSE_POSITIVE_TITLES = new Set(['MTA-STS policy file not accessible', 'MTA-STS policy redirects']);

/**
 * The package's not-assessed finding for a THROWN policy fetch (dns-checks ≥ 1.33.0, issue
 * #889) is identified by this `metadata.notAssessedReason` token — never by title, so a
 * copy edit in the package cannot silently re-enable a scored finding here. A robots.txt
 * abstention carries `'robots_disallowed'` instead and is left exactly as the package
 * labelled it (same vocabulary as ssl / http_security / bimi).
 */
const POLICY_FETCH_NOT_ASSESSED_REASON = 'policy_fetch_failed';

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
 *
 * ⚠️ The detail must NOT claim real sending MTAs are unaffected (issue #664). A sending MTA
 * is an automated, non-browser client — structurally the same class as this scanner — so an
 * edge rule aimed at automated clients as a class would reach it too and leave MTA-STS
 * genuinely unenforceable. We cannot distinguish that from a User-Agent-specific rule with
 * one intercepted fetch, so the wording states the ambiguity and names the distinguishing
 * signal instead of picking the optimistic branch. It must not assert the pessimistic branch
 * either — both are unmeasured. Enforced by test/check-mta-sts-waf.spec.ts.
 */
function buildPolicyWafFinding(domain: string, event: WafEvent, status: number): Finding {
	const provider = event.provider.charAt(0).toUpperCase() + event.provider.slice(1);
	const isBlock = event.kind === 'block';
	const title = isBlock
		? `${provider} WAF blocked policy fetch — accessibility inconclusive`
		: `${provider} WAF challenge intercepted — policy accessibility inconclusive`;
	const interception = isBlock ? 'block' : 'challenge';
	const detail =
		`The MTA-STS policy fetch for https://mta-sts.${domain}/.well-known/mta-sts.txt was intercepted by a ${provider} ${interception} page (HTTP ${status}), not served by the origin, so policy accessibility could not be verified externally by the scanner. ` +
		`Whether real sending MTAs reach the policy is undetermined: a sending MTA is an automated, non-browser client, so a rule that ${interception}s automated clients as a class would reach it too and leave MTA-STS unenforceable, while one keyed to this scanner's User-Agent would not. ` +
		`Check which applies by reviewing the ${provider} rule covering mta-sts.${domain}, or by requesting the policy with a neutral non-browser User-Agent.`;
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
 * The policy fetch THREW (WAF stall → AbortError, a network error, or a budget cut) and the
 * package returned its not-assessed shape (issue #889). Swap the package's generic
 * not-assessed finding for the WAF-aware inconclusive `info` note, and pin the category to
 * the EXCLUDED-and-RETRYABLE shape — `checkStatus: 'error'`, same as a Response-based WAF
 * event. Conservative: only invoked when we actually observed a policy-fetch throw, so a
 * genuine deterministic "not accessible" (a real 404 Response) is untouched and keeps the
 * package's `high`.
 *
 * A robots.txt disallow is returned verbatim: the package labels it with the shared
 * `robotsAbstentionMetadata` vocabulary (`notAssessedReason: 'robots_disallowed'`) and
 * already uses `checkStatus: 'error'`; rewording it as a "stall" would misattribute a
 * deliberate, polite abstention to a network fault.
 *
 * Why `'error'` and not the package's `'timeout'`: `scan_domain`'s `shouldRetry` fires on
 * `checkStatus === 'error' && score === 0` ONLY — `'timeout'` is the safeCheck-killed shape
 * and is deliberately never retried. A transient stall must get its second, unbudgeted
 * attempt (test/mta-sts-fetch-budget.spec.ts drives that recovery), so the Worker path
 * normalises to the retryable class. Direct package consumers keep the faithful `'timeout'`.
 */
function excludeForPolicyThrow(result: CheckResult, domain: string, err: unknown): CheckResult {
	if (err instanceof RobotsDisallowedError) return result;

	const isPackageNotAssessed = (f: Finding) => f.metadata?.notAssessedReason === POLICY_FETCH_NOT_ASSESSED_REASON;
	// The package emitted something other than its not-assessed shape — don't touch it.
	if (!result.checkStatus && !result.findings.some(isPackageNotAssessed)) return result;

	const kept = result.findings.filter((f: Finding) => !isPackageNotAssessed(f));
	// Unlike a Response-based WAF event, a throw carries NO provider evidence — do NOT
	// fabricate a `wafEvent` provider in the metadata (it would mislead analytics). Build a
	// plain inconclusive transient finding; `checkStatus: 'error'` below is what excludes the
	// category, not the finding metadata. `errorKind: 'timeout'` follows the repo's transient
	// convention (see lib/dns-error-result.ts).
	//
	// No `missingControl: true` (issue #638) — see the contract note on `buildWafFinding` in
	// lib/waf-detection.ts. A stalled/aborted policy fetch measured nothing, so it must not also
	// claim the control is absent; the `checkStatus: 'error'` below is what excludes the category.
	//
	// Nor may it claim real sending MTAs are unaffected (issue #664) — see the note on
	// `buildPolicyWafFinding` above. A stall carries even less evidence than an intercepted
	// Response: no provider, no kind, no status. State the ambiguity, assert neither branch.
	const inconclusive = createFinding(
		'mta_sts',
		'MTA-STS policy fetch stalled — accessibility inconclusive',
		'info',
		`The MTA-STS policy fetch for https://mta-sts.${domain}/.well-known/mta-sts.txt did not complete (the connection was aborted or stalled), ` +
			`so policy accessibility could not be verified externally by the scanner. This is consistent with a transient network failure or with an edge/WAF rule, ` +
			`and whether real sending MTAs would hit the same obstacle is undetermined: a sending MTA is an automated, non-browser client, so a rule aimed at automated clients as a class ` +
			`would stall them too and leave MTA-STS unenforceable, while one keyed to this scanner's User-Agent would not. Retry, and review any edge rule covering mta-sts.${domain}.`,
		{ inconclusive: true, errorKind: 'timeout' },
	);
	// `partial: true` mirrors the package: a transient outcome must not be cached for the
	// 5-min TTL on the direct registry path (handlers/tools.ts caches only `!r.partial`).
	return {
		...buildCheckResult('mta_sts', [...kept, inconclusive], result.controlPresent, result.recordPresent),
		score: 0,
		passed: false,
		checkStatus: 'error',
		partial: true,
	};
}

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 *
 * @param options.budgetMs - total wall-clock this check's fetches may collectively
 *   consume (issue #674). Absent (every direct call) → unchanged behaviour.
 */
export async function checkMtaSts(
	domain: string,
	dnsOptions?: QueryDnsOptions,
	zone?: ZoneContext,
	options?: {
		/**
		 * Wall-clock this check's fetches may collectively spend (issue #674).
		 *
		 * ⚠️ The `timeout` this wrapper passes to `checkMTASTS` below does NOT bound the
		 * policy fetch: the package hardcodes `AbortSignal.timeout(4000)` from its OWN
		 * module-local constant there and spends `options.timeout` on the DNS queries only
		 * (verified in packages/dns-checks/src/checks/check-mta-sts.ts). So the two external
		 * legs — the robots.txt gate (3s) and the policy fetch (4s) — run strictly
		 * sequentially at 7s combined, unbounded by anything this wrapper could pass, inside
		 * `scan_domain`'s 8s per-check budget and after the TXT lookup has already spent some
		 * of it. That made `mta_sts` the last scan check that lost DETERMINISTICALLY under a
		 * reduced per-check timeout: `safeCheck` killed it and the whole category went.
		 *
		 * With a budget each fetch is bounded by what the earlier legs left, so the check
		 * returns and REPORTS what it measured. A budget-cut policy fetch is observed exactly
		 * like a WAF stall (see `excludeForPolicyThrow`): the category is EXCLUDED as
		 * inconclusive, never reported as "no policy" — the measurement did not happen, so no
		 * claim about the control may be made from it.
		 */
		budgetMs?: number;
	},
): Promise<CheckResult> {
	// The clock starts HERE, before the zone/TXT lookups, because the deadline it
	// enforces is "this check must land before safeCheck kills it" — an absolute one
	// covering everything the check does, not a per-fetch allowance. DNS spends real
	// time ahead of the fetches and is metered by its own layer, so what is left for
	// the two HTTPS legs is exactly what this budget will hand them.
	const budget = createFetchBudget(options?.budgetMs);
	const gate = resolveGatedFetch(budget, options?.budgetMs !== undefined);
	const resolvedZone = zone ?? (await resolveZoneApex(domain, dnsOptions));
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
	let policyFetchError: unknown = null;

	const observingFetch = async (url: string, init?: RequestInit): Promise<Response> => {
		const policy = isPolicyFetch(url);
		let response: Response;
		try {
			response = await gate(url, init);
		} catch (err) {
			// A policy-fetch rejection (AbortError from a stalled WAF challenge, or a network
			// TypeError) is observed as inconclusive, then RE-THROWN so the package still runs
			// its own catch path and returns its not-assessed shape (#889). Only the FIRST
			// policy throw is recorded (single-fetch contract).
			//
			// The `!budget.canIssueRequest()` disjunct is what keeps a BUDGETED run honest
			// (#674): when the budget is already spent, `wrap` rejects with a plain `Error`
			// carrying neither the `AbortError` name nor `TypeError`, so `isObservableFetchThrow`
			// alone would leave the wrapper's WAF-aware prose unapplied (the package still abstains,
			// #889) for a probe that was never issued — pre-#889 it let a confident `medium` SCORE. Reading the budget state instead
			// of the error's message keeps the sentinel string out of this file's contract.
			// With no budget `remainingMs()` is Infinity, so this disjunct is constant-false and
			// the direct-call path is unchanged.
			if (policy && !policyFetchThrew && (isObservableFetchThrow(err) || !budget.canIssueRequest())) {
				policyFetchThrew = true;
				policyFetchError = err;
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
		zone: resolvedZone,
	})) as CheckResult;

	if (policyWafEvent) return excludeForWaf(result, domain, policyWafEvent, policyWafStatus);
	if (policyFetchThrew) return excludeForPolicyThrow(result, domain, policyFetchError);
	return result;
}

/**
 * Only treat a policy-fetch rejection as inconclusive when it looks like a stall /
 * network failure (AbortError from the package's AbortSignal.timeout, or a TypeError
 * network error). Anything else is re-thrown unobserved so the package owns it.
 */
function isObservableFetchThrow(err: unknown): boolean {
	if (err instanceof RobotsDisallowedError) return true;
	if (err instanceof Error) {
		return err.name === 'AbortError' || err.name === 'TimeoutError' || err instanceof TypeError;
	}
	return false;
}
