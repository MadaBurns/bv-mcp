// SPDX-License-Identifier: BUSL-1.1

import { type CheckCategory, type CheckResult, type Finding, buildCheckResult, createFinding } from '../../lib/scoring';
import { queryTxtRecords } from '../../lib/dns';
import { queryDnsRecords } from '../../lib/dns-records';
import { detectProviderMatches, detectProviderMatchesBySelectors, loadProviderSignatures } from '../../lib/provider-signatures';
import { detectCloudflareFallback } from '../../lib/cdn-fallback-detection';
import { type AsnDohResolver, detectCdnFromAsn } from '../../lib/cdn-asn-detection';
import { parseDmarcTags } from '../check-dmarc';
import { isCompletedCheck } from '../../lib/ungraded-display';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';

export interface ScanRuntimeOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
	profile?: 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal' | 'auto' | 'authoritative_dns_infra';
	profileAccumulator?: DurableObjectNamespace;
	/**
	 * ProfileAccumulator write-sharding mode (R10 PROPOSAL, default-off).
	 * `'global'` (default/undefined): legacy single "global" DO instance — unchanged.
	 * `'profile'`: shard the accumulator by scoring profile (6 fixed instances) so
	 * adaptive-weight writes spread across ~6 DO input gates. Both the /ingest write
	 * and the /weights read co-route by profile, so the partition is loss-free.
	 * Operator-only; must be wired from env before it has any effect.
	 */
	profileAccumulatorShardMode?: import('../../lib/profile-accumulator').AccumulatorShardMode;
	/**
	 * Analytics client (threaded structurally from `ToolRuntimeOptions`). Used by
	 * the adaptive-weight read path to emit the `shard_below_benchmark_floor`
	 * warm-up degradation signal when a per-profile shard is below
	 * `MIN_BENCHMARK_SCANS` while sharding is ON. Optional/no-op-safe.
	 */
	analytics?: import('../../lib/analytics').AnalyticsClient;
	waitUntil?: (promise: Promise<unknown>) => void;
	scoringConfig?: import('@blackveil/dns-checks/scoring').ScoringConfig;
	/** Override cache TTL in seconds (default: 300). Clamped to [60, 3600]. */
	cacheTtlSeconds?: number;
	/** Scan-level wall-clock budget in milliseconds. Defaults to SCAN_TIMEOUT_MS. */
	scanTimeoutMs?: number;
	/** Per-check wall-clock budget in milliseconds. Defaults to PER_CHECK_TIMEOUT_MS. */
	perCheckTimeoutMs?: number;
	/**
	 * Cap on concurrent outbound DoH fetches within this scan's fan-out. Defaults
	 * to SCAN_DNS_CONCURRENCY. Bounds tail-latency / subrequest pressure only — it
	 * does NOT change scan results. Threaded into `scanDns.dnsSemaphore`.
	 */
	dnsConcurrency?: number;
	/** Invocation-scoped semaphore shared by nested scans (for example batch_scan). */
	dnsSemaphore?: import('../../lib/semaphore').Semaphore;
	/** Parent request/job cancellation. Aborts the scan and suppresses cache writes. */
	signal?: AbortSignal;
	/** Custom secondary DoH resolver config (bv-dns). Threaded to scanDns but only active when skipSecondaryConfirmation is false. */
	secondaryDoh?: import('../../lib/dns-types').SecondaryDohConfig;
	/** Optional service binding for raw DNS, routing, and vantage-point probes. */
	infraProbe?: { fetch: typeof fetch };
	/** Operator-only bv-tls-probe service binding (negotiated-TLS-version detection for `ssl`; served-certificate capture for `dane_https` pin verification, #841). Fail-soft; absent on BSL self-hosts → scan `ssl` / `dane_https` scores unchanged. */
	tlsProbeBinding?: { fetch: typeof fetch };
	/** Bearer token forwarded to bv-tls-probe. */
	tlsProbeAuthToken?: string;
	/**
	 * Optional service binding to bv-certstream-worker. When present, the
	 * Cloudflare-CDN attribution heuristic sources cert issuer from /cert-meta
	 * (activates the v3.3.17 2-of-3 third signal). Without it, the heuristic
	 * degrades to NS+IP-only.
	 */
	certstream?: { fetch: typeof fetch };
	/** Bearer token for the bv-certstream-worker admin auth gate. */
	certstreamAuthToken?: string;
	/** Bypass cache and run a fresh scan. Useful for troubleshooting after DNS changes. */
	forceRefresh?: boolean;
	/** Internal: scan target inherits its DNS zone rather than owning a delegation. */
	nonApexHost?: boolean;
	/**
	 * Auth tier of the requesting principal. Threaded from ToolRuntimeOptions so
	 * scan_domain can gate paid-tier enrichments (e.g. TLS probe Browser Rendering).
	 */
	authTier?: string;
}

export async function applyScanPostProcessing(
	domain: string,
	checkResults: CheckResult[],
	runtimeOptions?: ScanRuntimeOptions,
): Promise<CheckResult[]> {
	let results = checkResults;
	const mxResult = results.find((result) => result.category === 'mx');

	// ONE non-mail predicate, keyed on a STRUCTURAL signal (#643).
	//
	// This used to be two predicates: a `hasNoMx` that tested for a finding titled
	// 'No MX records found' — a string NO production code path emits — and this
	// `mxDeclaresNoInboundMail`, added later for the wording branch only. `hasNoMx`
	// was therefore permanently `false` against real DNS, so `adjustForNonMailDomain`
	// (the documented "parent DMARC covers it → downgrade email-auth findings to
	// info" rule) had never once run in production, and non-mail domains carried
	// un-downgraded critical/high findings for controls that cannot apply to them.
	// The two are now unified: there is exactly one answer to "does this domain
	// accept inbound mail", and both the severity branch and the wording branch
	// read it.
	const declaresNoInboundMail = mxDeclaresNoInboundMail(mxResult);

	if (declaresNoInboundMail) {
		// A non-delegated host such as www.example.com can legitimately have no MX
		// or mail-auth records of its own. Preserve its web/TLS checks, but do not
		// report absent host-label mail records as security failures.
		if (runtimeOptions?.nonApexHost) {
			results = adjustForNonApexNonMailHost(results);
		}

		// The downgrade is GATED on real inherited protection, not on MX absence alone.
		//
		// Absent MX means the domain cannot RECEIVE mail. It says nothing about whether
		// the domain can be SPOOFED AS A SENDER — SPF/DKIM/DMARC protect outbound
		// identity, and a null-MX domain is still a forgeable From:. Downgrading missing
		// email-auth to `info` on MX absence alone would hand an A+ to a domain that
		// `check_mx` simultaneously reports as spoofable.
		//
		// So we downgrade only where the parent's DMARC `sp=`/`p=` is actually
		// `quarantine`/`reject` — i.e. inherited enforcement genuinely covers this name.
		// That is what CLAUDE.md has always documented ("parent DMARC sp=/p= →
		// downgrade"); the ungated form was an implementation drift that never ran.
		// Apex domains have no parent to inherit from, so they correctly never qualify.
		if (await checkApexDmarcPolicy(domain)) {
			results = adjustForNonMailDomain(results);
		}
		results = adjustBimiForNonMailDomain(results);
	} else if (mxResult) {
		results = clarifyMtaStsForMailDomain(domain, results);
	}

	// Detect no-send SPF policy (v=spf1 -all with no authorizing mechanisms)
	const spfResult = results.find((result) => result.category === 'spf');
	const hasNoSendPolicy = spfResult?.findings.some((f: Finding) => f.metadata?.noSendPolicy === true) ?? false;
	if (hasNoSendPolicy && !declaresNoInboundMail) {
		results = adjustForNoSendDomain(results);
	}

	// BIMI applicability wording (TEXT ONLY — severity and score untouched).
	// `adjustBimiForNonMailDomain` above only runs on the non-mail branch, so a
	// domain that declares "no mail" some *other* way — an SPF `-all` no-send
	// policy on a domain that still accepts inbound mail — kept the "eligible for
	// BIMI" sales pitch. Recommending BIMI to a domain that cannot send email is a
	// factual error, and it contradicts the same report's own no-send finding.
	if (!declaresNoInboundMail && hasNoSendPolicy) {
		results = adjustBimiForNonMailDomain(results);
	}

	// Impersonation escalation: a mail-sending domain whose DMARC is weak/absent
	// AND that has active lookalike/shadow impersonation domains is the brand-
	// justified critical case. Re-escalate the demoted DMARC finding to critical
	// so it is distinguishable from a routine mail domain with the same gap. Only
	// applies when the domain actually sends mail (has MX, not a no-send policy).
	if (!declaresNoInboundMail && !hasNoSendPolicy && hasActiveImpersonation(results) && dmarcIsWeak(results)) {
		results = escalateDmarcForImpersonation(results);
	}

	results = await addCdnHeuristics(domain, results, {
		certstream: runtimeOptions?.certstream,
		certstreamAuthToken: runtimeOptions?.certstreamAuthToken,
	});

	return addOutboundProviderInference(results, runtimeOptions);
}

/**
 * Heuristic CDN attribution fallback (tiered).
 *
 * Header-based CDN detection (in `check-http-security`) can miss CDNs that
 * don't emit a vendor-specific header, and cannot identify Cloudflare at all
 * from inside a Cloudflare Worker — see the rationale in
 * `src/lib/cdn-fallback-detection.ts`. `addCdnHeuristics` restores attribution
 * via three tiers, in order, each only running when the prior produced nothing:
 *
 *   1. Header vendor-specific — primary; if `http_security` already carries a
 *      `metadata.cdnProvider`, the fallbacks are skipped entirely.
 *   2. Cloudflare NS+IP+cert 2-of-3 heuristic (`detectCloudflareFallback`).
 *   3. ASN-based fallback (`detectCdnFromAsn`) — resolves A-record IPs to their
 *      origin ASN via team-cymru DoH and maps ASN -> CDN (closes the Akamai and
 *      other no-header-CDN false-negatives).
 *
 * When matched, emits a new info-level finding on the `http_security` check
 * with `metadata.cdnProvider`/`confidence: 'heuristic'`/`source` (`ns-and-ip-range`,
 * `ns-ip-and-cert`, or `asn-lookup`). Format-report already iterates findings
 * looking for `metadata.cdnProvider`, so it picks this up automatically.
 *
 * Conservative: any DNS error during the fresh NS/A lookups silently skips
 * the heuristic, and the ASN tier is bounded + fail-soft — never poisons a
 * scan result.
 */
/**
 * Sync budget for the cert-meta lookup inside scan_domain post-processing.
 * Cert issuer is a best-effort upgrade signal — any failure (including
 * timeout) silently falls back to certIssuer:null, which degrades the
 * 2-of-3 rule to the v3.3.15 NS+IP-only gate. crt.sh typically returns in
 * <1s; certspotter fallback inside the worker can take up to 10s, but we
 * cap the caller side here at 5s so the heuristic doesn't drag scan latency.
 */
const CERT_META_LOOKUP_TIMEOUT_MS = 5_000;
const CERT_META_MAX_BODY_BYTES = 64 * 1024;

/** @internal Exported for focused timeout/body regressions. */
export async function fetchCertIssuerFromCertstream(
	domain: string,
	certstream: { fetch: typeof fetch },
	authToken?: string,
	timeoutMs = CERT_META_LOOKUP_TIMEOUT_MS,
): Promise<string | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const response = await certstream.fetch(`https://certstream/cert-meta?domain=${encodeURIComponent(domain)}`, {
			...(authToken ? { headers: { Authorization: `Bearer ${authToken}` } } : {}),
			signal: controller.signal,
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return null;
		}
		const data = await readJsonResponseCapped<{ issuer?: string | null; error?: string }>(response, CERT_META_MAX_BODY_BYTES);
		if (!data) return null;
		if (data.error || !data.issuer) return null;
		return data.issuer;
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}

async function addCdnHeuristics(
	domain: string,
	results: CheckResult[],
	options?: { certstream?: { fetch: typeof fetch }; certstreamAuthToken?: string; doh?: AsnDohResolver },
): Promise<CheckResult[]> {
	const httpResult = results.find((result) => result.category === 'http_security');
	if (!httpResult) return results;

	// Tier 1: don't compete with a header-based CDN hit — those are stronger signal.
	const alreadyHasCdn = httpResult.findings.some((f) => typeof f.metadata?.cdnProvider === 'string');
	if (alreadyHasCdn) return results;

	let nsHosts: string[];
	let aRecords: string[];
	try {
		[nsHosts, aRecords] = await Promise.all([queryDnsRecords(domain, 'NS'), queryDnsRecords(domain, 'A')]);
	} catch {
		return results;
	}

	// Strip trailing dots for consistency with the helper's expected input.
	const normalisedNs = nsHosts.map((h) => h.replace(/\.$/, '').toLowerCase());

	// TLS cert issuer — sourced via the bv-certstream-worker /cert-meta
	// endpoint when the service binding is available. Without the binding,
	// or on lookup failure/timeout, fall back to null and let the 2-of-3 rule
	// degrade to the v3.3.15 NS+IP-only gate. This activates v3.3.17's
	// dormant third signal: Cloudflare customers using external DNS providers
	// (eg. shopify.com on Foundation DNS for NS, Cloudflare for CDN) now
	// flip from cdnProvider:null to cdnProvider:'Cloudflare' via IP+cert.
	let certIssuer: string | null = null;
	if (options?.certstream) {
		certIssuer = await fetchCertIssuerFromCertstream(domain, options.certstream, options.certstreamAuthToken);
	}

	// Tier 2: Cloudflare NS+IP+cert heuristic. When it produces nothing, fall
	// through to the ASN-based tier 3 below.
	const heuristic = detectCloudflareFallback({ nsHosts: normalisedNs, aRecords, certIssuer });
	if (!heuristic) {
		return addAsnCdnHeuristic(httpResult, results, aRecords, options?.doh);
	}

	// Build a detail string that honestly reflects which signals matched, so
	// users understand whether attribution came from (NS+IP) or (IP+cert) or
	// (NS+cert) — the three valid 2-of-3 combinations.
	const detailParts: string[] = [];
	const nsMatchedCf = normalisedNs.some((h) => h.endsWith('.ns.cloudflare.com'));
	const certMatchedCf = certIssuer !== null && /cloudflare/i.test(certIssuer);
	if (nsMatchedCf) detailParts.push('NS records on *.ns.cloudflare.com');
	if (aRecords.length > 0) detailParts.push("A records in Cloudflare's published edge ranges");
	if (certMatchedCf) detailParts.push(`TLS cert issuer matches Cloudflare (${certIssuer})`);

	const cdnFinding = createFinding(
		'http_security',
		'HTTP origin attributed to Cloudflare CDN (heuristic)',
		'info',
		`Cloudflare CDN inferred from 2-of-3 signals: ${detailParts.join('; ')}. Header-based CDN detection was inconclusive (the scanner runs inside a Cloudflare Worker, which rewrites server: cloudflare on every outbound response).`,
		{
			cdnProvider: 'Cloudflare',
			confidence: 'heuristic',
			source: certMatchedCf ? 'ns-ip-and-cert' : 'ns-and-ip-range',
			...(certIssuer ? { certIssuer } : {}),
		},
	);

	return appendCdnFinding(httpResult, results, cdnFinding);
}

/**
 * Tier 3: ASN-based CDN attribution fallback.
 *
 * Runs only when tiers 1 (header) and 2 (CF NS+IP+cert) produced no
 * attribution. Resolves up to MAX_ASN_LOOKUPS A-record IPs to their origin ASN
 * via team-cymru DoH TXT and maps ASN -> CDN (see cdn-asn-detection.ts). This
 * closes false-negatives for CDNs that don't emit a vendor-specific header —
 * notably Akamai (`Server: AkamaiGHost`, no transform header) — without a
 * hardcoded per-provider CIDR list.
 *
 * Best-effort and fail-soft: the resolver enforces its own per-query timeout,
 * the lookup count is bounded, and any failure yields no attribution.
 */
async function addAsnCdnHeuristic(
	httpResult: CheckResult,
	results: CheckResult[],
	aRecords: string[],
	doh?: AsnDohResolver,
): Promise<CheckResult[]> {
	if (aRecords.length === 0) return results;

	const resolver: AsnDohResolver = doh ?? { queryTxt: (name) => queryTxtRecords(name) };
	const asnResult = await detectCdnFromAsn(aRecords, resolver);
	if (!asnResult) return results;

	const cdnFinding = createFinding(
		'http_security',
		`HTTP origin attributed to ${asnResult.provider} CDN (heuristic)`,
		'info',
		`${asnResult.provider} CDN inferred from the origin ASN (AS${asnResult.asn}) of the resolved A-record IP via team-cymru. Header-based CDN detection was inconclusive — this CDN does not emit a vendor-specific response header, and the scanner runs inside a Cloudflare Worker, which rewrites server: cloudflare on every outbound response.`,
		{
			cdnProvider: asnResult.provider,
			confidence: asnResult.confidence,
			source: 'asn-lookup',
			asn: asnResult.asn,
		},
	);

	return appendCdnFinding(httpResult, results, cdnFinding);
}

/**
 * Append a heuristic CDN finding to the http_security check, preserving its
 * scoring fields (buildCheckResult creates a fresh CheckResult).
 */
function appendCdnFinding(httpResult: CheckResult, results: CheckResult[], cdnFinding: Finding): CheckResult[] {
	const updated = buildCheckResult('http_security', [...httpResult.findings, cdnFinding]);
	const merged: CheckResult = {
		...updated,
		score: httpResult.score,
		passed: httpResult.passed,
		checkStatus: httpResult.checkStatus,
		metadata: httpResult.metadata,
	};
	return upsertCheckResult(results, merged);
}

function extractSpfSignalDomains(result: CheckResult | undefined): string[] {
	if (!result) return [];

	const domains = new Set<string>();
	for (const finding of result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata !== 'object') continue;

		const includeDomains = metadata.includeDomains;
		if (Array.isArray(includeDomains)) {
			for (const domain of includeDomains) {
				if (typeof domain === 'string' && domain.trim().length > 0) {
					domains.add(domain.trim().toLowerCase());
				}
			}
		}

		const redirectDomain = metadata.redirectDomain;
		if (typeof redirectDomain === 'string' && redirectDomain.trim().length > 0) {
			domains.add(redirectDomain.trim().toLowerCase());
		}
	}

	return Array.from(domains);
}

function extractDkimSignalSelectors(result: CheckResult | undefined): string[] {
	if (!result) return [];

	const selectors = new Set<string>();
	for (const finding of result.findings) {
		const metadata = finding.metadata;
		if (!metadata || typeof metadata !== 'object') continue;

		const selectorsFound = metadata.selectorsFound;
		if (!Array.isArray(selectorsFound)) continue;

		for (const selector of selectorsFound) {
			if (typeof selector === 'string' && selector.trim().length > 0) {
				selectors.add(selector.trim().toLowerCase());
			}
		}
	}

	return Array.from(selectors);
}

function upsertCheckResult(results: CheckResult[], updated: CheckResult): CheckResult[] {
	return results.map((result) => (result.category === updated.category ? updated : result));
}

async function addOutboundProviderInference(results: CheckResult[], runtimeOptions?: ScanRuntimeOptions): Promise<CheckResult[]> {
	// If the MX provider detection failed, skip provider-informed DKIM/SPF adjustments
	// to avoid false inferences based on incomplete or degraded provider data.
	const mxResult = results.find((result) => result.category === 'mx');
	const providerDetectionFailed = Boolean(
		(mxResult?.metadata as { providerDetectionFailed?: boolean } | undefined)?.providerDetectionFailed,
	);
	if (providerDetectionFailed) return results;

	const spfResult = results.find((result) => result.category === 'spf');
	const dkimResult = results.find((result) => result.category === 'dkim');

	const signalDomains = extractSpfSignalDomains(spfResult);
	const dkimSelectors = extractDkimSignalSelectors(dkimResult);
	if (signalDomains.length === 0 && dkimSelectors.length === 0) return results;

	const signatures = await loadProviderSignatures({
		sourceUrl: runtimeOptions?.providerSignaturesUrl,
		allowedHosts: runtimeOptions?.providerSignaturesAllowedHosts,
		expectedSha256: runtimeOptions?.providerSignaturesSha256,
	});
	const signatureSet = signatures.outbound.length > 0 ? signatures.outbound : signatures.inbound;
	const hostMatches = detectProviderMatches(signalDomains, signatureSet);
	const selectorMatches = detectProviderMatchesBySelectors(dkimSelectors, signatureSet);

	const mergedMatches = new Map<string, Set<string>>();
	for (const match of [...hostMatches, ...selectorMatches]) {
		if (!mergedMatches.has(match.provider)) {
			mergedMatches.set(match.provider, new Set<string>());
		}
		for (const evidence of match.matches) {
			mergedMatches.get(match.provider)?.add(evidence);
		}
	}

	const outboundMatches = Array.from(mergedMatches.entries()).map(([provider, matches]) => ({
		provider,
		matches: Array.from(matches),
	}));
	if (outboundMatches.length === 0) return results;

	const providerNames = outboundMatches.map((match) => match.provider).join(', ');
	const evidence = outboundMatches.map((match) => `${match.provider}: ${match.matches.join(', ')}`).join('; ');
	const signalBoost = signalDomains.length > 0 && dkimSelectors.length > 0 ? 0.05 : 0;
	const baseConfidence = signatures.source === 'runtime' ? 0.85 : signatures.source === 'stale' ? 0.7 : 0.65;
	const providerConfidence = Math.min(0.95, baseConfidence + signalBoost);

	const spfBaseline = spfResult ?? buildCheckResult('spf', []);
	const updatedSpf = buildCheckResult('spf', [
		...spfBaseline.findings,
		createFinding('spf', 'Outbound email provider inferred', 'info', `Outbound provider(s): ${providerNames}. Evidence: ${evidence}.`, {
			detectionType: 'outbound',
			providers: outboundMatches.map((match) => ({ name: match.provider, matches: match.matches })),
			signalsUsed: {
				spfDomains: signalDomains,
				dkimSelectors,
			},
			providerConfidence,
			signatureSource: signatures.source,
			signatureVersion: signatures.version,
			signatureFetchedAt: signatures.fetchedAt,
		}),
	]);

	return upsertCheckResult(results, updatedSpf);
}

function getParentDomain(domain: string): string | null {
	const parts = domain.split('.');
	if (parts.length <= 2) return null;
	return parts.slice(1).join('.');
}

async function checkApexDmarcPolicy(domain: string): Promise<boolean> {
	const parent = getParentDomain(domain);
	if (!parent) return false;

	try {
		const records = await queryTxtRecords(`_dmarc.${parent}`);
		const dmarcRecord = records.find((record) => record.toLowerCase().startsWith('v=dmarc1'));
		if (!dmarcRecord) return false;

		const tags = parseDmarcTags(dmarcRecord);
		const effectivePolicy = tags.get('sp') || tags.get('p') || '';
		return effectivePolicy === 'quarantine' || effectivePolicy === 'reject';
	} catch {
		return false;
	}
}

function isMissingRecordFinding(finding: { title: string; detail: string }): boolean {
	// Match against title only (controlled by check modules, not DNS data) to avoid ReDoS on attacker-controlled detail strings
	const title = finding.title.toLowerCase();
	return (
		title.includes('missing') ||
		title.includes('not found') ||
		title.includes('no mta-sts') ||
		title.includes('no dkim') ||
		/^no\s+\S+\s+record/.test(title)
	);
}

/**
 * LEGACY-ONLY fallback: MX finding titles that mean "this domain does not accept
 * inbound email", consulted only when `controlPresent` is absent from the result.
 *
 * The first four are the ACTUAL titles `check-mx` emits on its non-mail terminal
 * paths (`packages/dns-checks/src/checks/check-mx.ts` + `mx-analysis.ts`) — but
 * every one of those paths also sets `controlPresent: false`, so in production
 * this set is never reached. `'No MX records found'` is emitted by NOTHING; it is
 * the phantom title that made the old `hasNoMx` permanently false (#643), kept
 * here so synthetic/older-vintage results are still recognised.
 *
 * Do NOT add new titles here. Cross-module finding identity by string literal has
 * no compile-time or test-time link to its producer and fails silently forever —
 * which is exactly how this defect survived. Key on structure (`controlPresent`).
 */
const NO_INBOUND_MAIL_MX_TITLES: ReadonlySet<string> = new Set([
	'Null MX record (RFC 7505)',
	'Correctly-configured non-mail domain',
	'Non-mail domain SPF not hard-fail',
	'No MX and no SPF — domain spoofable',
	'No MX records found',
]);

/**
 * The single answer to "did the `mx` check DEFINITIVELY establish that this domain
 * accepts no inbound email" — either no MX records at all, or an RFC 7505 null MX.
 *
 * Gates BOTH halves of non-mail post-processing: the wording branches AND
 * `adjustForNonMailDomain()`, which downgrades missing-record email findings to
 * `info`. Those were split across two predicates until #643 — one structural, one
 * matching a finding title nothing emits — so the scan's prose and its severities
 * could disagree about whether the same domain handled mail. One predicate makes
 * that class of divergence unrepresentable.
 *
 * ## Absence is asserted only from a completed measurement
 *
 * Two independent guards, because "no mail" is a claim we make about the domain,
 * not merely the absence of a signal:
 *
 *  1. `checkStatus` must be measured. A transient resolver failure returns
 *     `checkStatus: 'error'` — we could not observe the mail posture, so we make no
 *     claim about it. (This is invariant #3 in `unmeasured-check-exemption.audit`,
 *     which has already caught this exact shape three times.)
 *  2. `controlPresent`, which `check-mx` sets on every terminal path: `true` only
 *     when real mail-routing MX records were observed, `false` for both the no-MX
 *     and the null-MX declarations, `undefined` when inconclusive.
 *
 * A mail-sending domain (`controlPresent: true`) and an inconclusive lookup both
 * return `false` here, so neither is ever treated as non-mail.
 */
export function mxDeclaresNoInboundMail(mxResult: CheckResult | undefined): boolean {
	if (!mxResult) return false;
	// Never assert "no inbound mail" from a probe that did not complete.
	if (!isCompletedCheck(mxResult)) return false;
	if (mxResult.controlPresent === false) return true;
	if (mxResult.controlPresent === true) return false;
	return mxResult.findings.some((finding: Finding) => NO_INBOUND_MAIL_MX_TITLES.has(finding.title));
}

/**
 * Rewrite the MTA-STS "both records missing" summary to name inbound mail as the
 * reason it matters — but ONLY for a domain that actually accepts inbound mail.
 *
 * The caller gates this on `!mxDeclaresNoInboundMail(mxResult)`. Without that
 * gate a null-MX domain was told "Since this domain has MX records and accepts
 * email…" in the very same response that reported "Null MX record (RFC 7505) —
 * Domain explicitly declares it does not accept email". `check-mta-sts` already
 * branches its own copy on a real MX probe (`detectInboundMail`), so for a
 * non-mail domain the correct wording is the one the check itself produced and
 * the right action here is to leave it alone.
 *
 * The gate stays permissive on an INCONCLUSIVE MX result so this keeps serving
 * its original purpose: correcting the check's non-mail copy when the check's own
 * MX probe failed but the scan's `mx` check found real mail routing.
 */
function clarifyMtaStsForMailDomain(domain: string, results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'mta_sts') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No MTA-STS or TLS-RPT records found') {
				return {
					...finding,
					detail: `Neither MTA-STS nor TLS-RPT records are present for ${domain}. Since this domain has MX records and accepts email, adding MTA-STS and TLS-RPT is recommended to protect inbound email in transit.`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

function adjustForNonApexNonMailHost(results: CheckResult[]): CheckResult[] {
	const mailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts', 'bimi', 'tlsrpt', 'dane', 'subdomailing'];
	return results.map((result) => {
		if (!mailCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				return {
					...finding,
					severity: 'info' as const,
					detail: `${finding.detail} (not applicable — this non-apex host has no MX; mail controls are evaluated at its mail domain)`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

function adjustForNonMailDomain(results: CheckResult[]): CheckResult[] {
	const emailCategories: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'mta_sts', 'subdomailing'];
	return results.map((result) => {
		if (!emailCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				// Callers gate this on enforcing parent DMARC, so the covering wording is
				// unconditional here. The old two-branch version had `severity: 'info'`
				// OUTSIDE the conditional, so the boolean only picked prose while every
				// no-MX domain got the downgrade — keep this single-branch to prevent a
				// re-introduction of that split.
				const reason = 'expected — no MX records and parent domain DMARC policy covers subdomains';
				return { ...finding, severity: 'info' as const, detail: `${finding.detail} (${reason})` };
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

/**
 * Replace the "eligible for BIMI" recommendation with a non-applicability note on
 * a domain that does not send email (no MX / RFC 7505 null MX / SPF `-all`
 * no-send policy).
 *
 * TEXT ONLY — severity, metadata, and therefore the category score are untouched;
 * only the `detail` prose of the one matching finding changes. `scan_domain`
 * already handles the category correctly (`bimi` lands in
 * `notApplicableCategories` with a null score); this closes the prose half.
 */
function adjustBimiForNonMailDomain(results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'bimi') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No BIMI record found' && finding.detail.includes('eligible for BIMI')) {
				// Trim the sentence-terminating dot the greedy \S+ swallows, else the
				// rewritten detail reads "…default._bimi.example.com.. This domain…".
				const bimiDomain = (finding.detail.match(/at (default\._bimi\.\S+)/)?.[1] ?? `default._bimi.unknown`).replace(/\.+$/, '');
				return {
					...finding,
					detail: `No BIMI record found at ${bimiDomain}. This domain does not appear to send email, so BIMI is not applicable.`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

/**
 * Active brand impersonation is signalled by a medium-or-higher `lookalikes`
 * finding (a calibrated lookalike/typosquat with real infrastructure). Info-level
 * findings — defensive registrations, shared-NS matches — are deliberately excluded.
 *
 * TASK 7B (2026-07-27) — what a medium-or-higher `lookalikes` finding MEANS.
 * The severities this predicate sees come from the THREAT-OBSERVATION axis
 * (`metadata.findingAxis === 'threat_observation'`): the #264-calibrated
 * per-candidate observations about infrastructure (e.g. a confusable domain
 * with live MX on a disposable provider), the aggregate HIGH summary, and — on
 * an operator deploy with the BV_RECON binding — the `'medium'` CT-corroboration
 * finding. ATTRIBUTION-axis findings (`'attribution'`) are capped at `info` for
 * every non-`owned_by_seed` verdict and can never trip this, and an
 * `owned_by_seed` candidate emits no threat finding at all — so the DMARC
 * escalation is keyed on OBSERVED impersonation-shaped infrastructure, never on
 * an ownership claim about a third party's domain.
 *
 * CORRECTION (fix round 1, F3): an earlier revision of this note claimed the
 * predicate was "unreachable" under Task 7 because every `lookalikes` finding
 * was capped at `info`. That was FALSE — the recon CT-corroboration finding has
 * never been routed through the ownership gate and emits `'medium'` regardless.
 * The Task 7 gate broke the DNS-derived path only; 7b restored it.
 *
 * This keys on `lookalikes` ONLY, deliberately matching the `impersonation_weak_dmarc`
 * interaction rule in `category-interactions.ts`, which scores `lookalikes <= 85`
 * (≈ "at least one medium-or-higher finding"). Keeping the label-escalation here and
 * the score-penalty there on the *same* signal is what prevents a critical label that
 * carries no score consequence. `shadow_domains` is a valid corroborator but is left
 * out of BOTH sides for now — adding it would require a parallel interaction rule to
 * stay coherent (see the note in category-interactions.ts).
 */
function hasActiveImpersonation(results: CheckResult[]): boolean {
	const lookalikes = results.find((result) => result.category === 'lookalikes');
	if (!lookalikes) return false;
	return lookalikes.findings.some(
		(finding: Finding) => finding.severity === 'medium' || finding.severity === 'high' || finding.severity === 'critical',
	);
}

/** Weak DMARC = no record at all, or a published p=none policy (the two demoted findings). */
function dmarcIsWeak(results: CheckResult[]): boolean {
	const dmarc = results.find((result) => result.category === 'dmarc');
	if (!dmarc) return false;
	return dmarc.findings.some(
		(finding: Finding) => finding.title === 'No DMARC record found' || finding.title === 'DMARC policy set to none',
	);
}

/** Re-escalate the weak-DMARC finding(s) to critical, recording why. */
function escalateDmarcForImpersonation(results: CheckResult[]): CheckResult[] {
	return results.map((result) => {
		if (result.category !== 'dmarc') return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if (finding.title === 'No DMARC record found' || finding.title === 'DMARC policy set to none') {
				return {
					...finding,
					severity: 'critical' as const,
					detail: `${finding.detail} (escalated — active lookalike/impersonation domains were detected for this domain, so weak DMARC enforcement is an exploitable spoofing channel)`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}

function adjustForNoSendDomain(results: CheckResult[]): CheckResult[] {
	const noSendCategories: CheckCategory[] = ['dkim', 'mta_sts', 'bimi'];
	return results.map((result) => {
		if (!noSendCategories.includes(result.category)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			if ((finding.severity === 'critical' || finding.severity === 'high') && isMissingRecordFinding(finding)) {
				return {
					...finding,
					severity: 'info' as const,
					detail: `${finding.detail} (expected — domain SPF policy rejects all outbound mail)`,
				};
			}
			return finding;
		});
		return buildCheckResult(result.category, adjusted);
	});
}
