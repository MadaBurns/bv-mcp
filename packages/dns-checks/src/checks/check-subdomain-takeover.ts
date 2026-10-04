// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Takeover / Dangling CNAME Detection check.
 * Scans known/active subdomains for orphaned CNAME records pointing to
 * deleted/unresolved third-party services.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, FetchFunction, Finding, RawDNSQueryFunction } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { KNOWN_SUBDOMAINS, getNoTakeoverFinding, scanSubdomainForTakeoverInternal } from './subdomain-takeover-analysis';
import type { SweepDescriptor } from './subdomain-takeover-analysis';

/** Cap on caller-supplied subdomain lists to bound per-call DNS+HTTP cost. */
const MAX_SUBDOMAINS = 1000;

export interface SubdomainTakeoverOptions {
	timeout?: number;
	fetchFn?: FetchFunction;
	/**
	 * Optional explicit subdomain list (full FQDNs or short labels). When
	 * provided, this list is swept *instead of* the built-in 15-name
	 * `KNOWN_SUBDOMAINS`. Caller is expected to source these from a real
	 * enumeration (CT logs, brand-audit discovery, etc.). Deduped and capped
	 * at `MAX_SUBDOMAINS` per call. A list that is cut by the cap is reported
	 * (`truncatedTo`) and the result is `partial`; a non-empty list with no usable
	 * name abstains (`caller_list_unusable`) — the built-in names are never silently
	 * substituted for a caller's list (#1201). An empty array means "no list".
	 */
	subdomains?: readonly string[];
	/**
	 * Cap on how many swept subdomains (in sweep order) run the #973 A/AAAA-only
	 * takeover vector. Undefined (every direct `check_subdomain_takeover` call) means
	 * no cap — every swept subdomain gets the full CNAME + A/AAAA sweep, unchanged
	 * from before #973. `scan_domain` passes a small cap to stay inside its shared
	 * DNS-query ceiling (test/hot-path-concurrency.perf.spec.ts); subdomains past the
	 * cap still get the CNAME leg, just not the A/AAAA leg. When the cap actually
	 * truncates the sweep, the all-clear finding discloses the vector as sampled
	 * rather than claiming full coverage.
	 */
	aRecordVectorSampleCap?: number;
	/**
	 * Optional raw-DoH-response query function. When supplied, it REPLACES the plain
	 * `queryDNS` calls on the CNAME/A/AAAA lookups this check performs, so the dangling
	 * record's answer TTL can be captured as finding evidence metadata at zero extra
	 * subrequest cost (mirrors `check-caa.ts`'s `rawQueryDNS` option). Omitted entirely,
	 * behaviour is byte-identical to before this option existed — TTL is simply absent
	 * from findings. TTL is evidence only; it is never a score input.
	 */
	rawQueryDNS?: RawDNSQueryFunction;
}

/**
 * Check for dangling CNAME records and provider-deprovisioned takeover
 * fingerprints. Default surface: 15 hardcoded "known" subdomain names
 * (`www`, `app`, `api`, etc.). Pass `options.subdomains` to sweep a real
 * enumeration instead.
 *
 * Requires a fetch function for HTTP fingerprint probing.
 */
export async function checkSubdomainTakeover(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: SubdomainTakeoverOptions,
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	// Default to a no-op fetch that never matches fingerprints if no fetchFn provided
	const fetchFn: FetchFunction = options?.fetchFn ?? (async () => new Response('', { status: 200 }));
	const findings: Finding[] = [];

	// #1201 — which list is being swept. A non-empty caller list is the sweep; if it
	// collapses to nothing usable the check abstains, it never substitutes the built-in
	// names for the caller's (that would answer a question the caller did not ask).
	const callerList = options?.subdomains !== undefined && options.subdomains.length > 0 ? options.subdomains : null;
	const dedupedCaller = callerList ? Array.from(new Set(callerList.map((s) => s.trim()).filter(Boolean))) : [];
	const truncated = dedupedCaller.length > MAX_SUBDOMAINS;
	const explicit = dedupedCaller.slice(0, MAX_SUBDOMAINS);
	const subdomainsToScan = callerList ? explicit : KNOWN_SUBDOMAINS;

	const aRecordCap = options?.aRecordVectorSampleCap;
	// True only when the cap actually cuts the sweep short — a cap ≥ the sweep size
	// checks every subdomain anyway and is not a sample.
	const aRecordVectorSampled = aRecordCap !== undefined && subdomainsToScan.length > aRecordCap;

	// The sweep denominator, computed once and stamped on EVERY finding returned below.
	const sweep: SweepDescriptor = {
		sweptCount: subdomainsToScan.length,
		sweepSource: callerList ? 'caller' : 'builtin',
		...(callerList ? { requestedCount: callerList.length } : {}),
		...(truncated ? { truncatedTo: MAX_SUBDOMAINS } : {}),
		...(aRecordVectorSampled ? { aRecordVectorSampledTo: aRecordCap } : {}),
	};
	// A caller list that was not fully swept is a partial answer: `partial: true` keeps it
	// out of both `!partial` cache predicates (#900 class).
	const finish = (found: Finding[]): CheckResult => {
		const result = buildCheckResult(
			'subdomain_takeover',
			found.map((f) => ({ ...f, metadata: { ...(f.metadata ?? {}), ...sweep } })),
		);
		return truncated ? { ...result, partial: true } : result;
	};

	if (callerList && explicit.length === 0) {
		return buildNotAssessedResult(
			'subdomain_takeover',
			createFinding(
				'subdomain_takeover',
				'Subdomain takeover not assessed — caller subdomain list unusable',
				'info',
				`The caller supplied ${callerList.length} subdomain entries for ${domain}, but none contained a usable name after trimming whitespace, so nothing was swept. The built-in ${KNOWN_SUBDOMAINS.length}-name list was deliberately not substituted for the caller's list. This is not evidence that the domain is free of dangling CNAMEs — the category is excluded from scoring rather than passed. Re-run with at least one non-blank subdomain, or omit the list to sweep the built-in names.`,
				{
					evidence: ['caller_list_unusable'],
					inconclusive: true,
					errorKind: 'invalid_input',
					reason: 'caller_list_unusable',
					...sweep,
				},
			),
			'error',
		);
	}

	const outcomes = await Promise.all(
		subdomainsToScan.map(async (subdomain, index) => ({
			subdomain,
			...(await scanSubdomainForTakeoverInternal(
				domain,
				subdomain,
				queryDNS,
				fetchFn,
				timeout,
				aRecordCap === undefined || index < aRecordCap,
				options?.rawQueryDNS,
			)),
		})),
	);

	for (const outcome of outcomes) {
		findings.push(...outcome.findings);
	}

	// A subdomain counts as measured only when its takeover question was actually answered.
	// Two ways it is not: the CNAME query threw (#948), or a third-party CNAME target's own
	// A query threw (#983) — the latter leaves us knowing the subdomain points at a
	// takeover-prone service and nothing about whether that service still holds the name.
	const unmeasured = outcomes.filter((o) => o.cnameQueryFailed || o.targetResolutionFailed).map((o) => o.subdomain);
	const answeredCount = outcomes.length - unmeasured.length;

	// Any non-`info` finding is real, DNS-derived evidence of a dangling record. It stands
	// on its own regardless of how many sibling probes failed — positive evidence is
	// monotone, so an unmeasured neighbour cannot invalidate it. The one finding that used
	// to reach this guard without being evidence (the thrown CNAME-target path) is now an
	// `info` abstention, so the comment is true as written (#983).
	if (findings.some((f) => f.severity !== 'info')) {
		return finish(findings);
	}

	// Issue #948 — abstain when ZERO swept subdomains answered.
	//
	// Every CNAME query threw, so `getNoTakeoverFinding` below would assert "no subdomain
	// takeover vectors detected" — score 100, passed, and written to the 5-minute cache —
	// for a sweep that never reached a resolver. `checkStatus: 'error'` is what makes the
	// scoring engine EXCLUDE the category (`isCheckMeasured`, scoring/evidence.ts) and what
	// arms scan_domain's transient-zero retry (`shouldRetry` requires `'error'`; a
	// `'timeout'` status is never retried); `partial: true` keeps the non-answer out of the
	// cache. The finding carries `inconclusive` + `errorKind` and deliberately NOT
	// `missingControl` — nothing was measured, so nothing can be claimed absent (#638 law).
	if (answeredCount === 0) {
		return buildNotAssessedResult(
			'subdomain_takeover',
			createFinding(
				'subdomain_takeover',
				'Subdomain takeover not assessed — every subdomain probe failed',
				'info',
				`No subdomain in the sweep for ${domain} was examined: all ${outcomes.length} probes failed, either because the CNAME lookup threw or because a third-party CNAME target could not be resolved. This is not evidence that the domain is free of dangling CNAMEs — the category is excluded from scoring rather than passed. Re-run the check once name resolution is working.`,
				{
					// No `verificationStatus`: the TakeoverVerificationStatus union describes
					// outcomes of a completed probe, and nothing was probed. Matches the Worker
					// wrapper's cut-probe note, which omits it for the same reason.
					evidence: ['cname_sweep_failed'],
					inconclusive: true,
					errorKind: 'dns_error',
					subdomainsUnmeasured: unmeasured,
					...sweep,
				},
			),
			'error',
		);
	}

	// Some probes answered: the clean verdict stands, narrowed to the subdomains that were
	// actually swept so the scope of the claim stays auditable. An inconclusive finding does
	// not suppress it — a subdomain whose target could not be resolved (#983) is disclosed
	// through `subdomainsUnmeasured` exactly like a subdomain whose CNAME query threw, and
	// without this the result would carry only an "it failed" note and no verdict at all.
	if (findings.every((f) => (f.metadata as { inconclusive?: boolean } | undefined)?.inconclusive === true)) {
		const clean = getNoTakeoverFinding(domain, { aRecordVectorSampled, sweep });
		findings.push(
			unmeasured.length > 0
				? { ...clean, metadata: { ...(clean.metadata ?? {}), subdomainsUnmeasured: unmeasured } }
				: clean,
		);
	}

	return finish(findings);
}
