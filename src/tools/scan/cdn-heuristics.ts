// SPDX-License-Identifier: BUSL-1.1

/** scan_domain post-processing: heuristic CDN attribution on the `http_security` result (Cloudflare NS+IP+cert, then ASN). */

import { type CheckResult, type Finding, createFinding } from '../../lib/scoring';
import { queryTxtRecords } from '../../lib/dns';
import { queryDnsRecords } from '../../lib/dns-records';
import { detectCloudflareFallback } from '../../lib/cdn-fallback-detection';
import { type AsnDohResolver, detectCdnFromAsn } from '../../lib/cdn-asn-detection';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';
import { certstreamHeaders } from '../../lib/certstream-headers';
import { upsertCheckResult, rebuildPreservingSignals } from './result-rebuild';

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
			headers: certstreamHeaders(authToken),
			signal: controller.signal,
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return null;
		}
		// A typed JSON read does not validate the wire schema. In particular an
		// issuer array would be coerced into a Cloudflare match by downstream RegExp.test.
		// The existing body cap bounds the string; health or malformed payloads provide no issuer evidence.
		const data = await readJsonResponseCapped<unknown>(response, CERT_META_MAX_BODY_BYTES);
		if (data === null || typeof data !== 'object' || Array.isArray(data)) return null;
		if (!('issuer' in data) || typeof data.issuer !== 'string' || data.issuer.trim().length === 0) return null;
		if ('error' in data && data.error) return null;
		return data.issuer;
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}

export async function addCdnHeuristics(
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
 *
 * `metadata` used to be re-attached by hand in the merge below; `controlPresent`
 * and `recordPresent` were not, so they were dropped here too (#994). Latent
 * rather than live — nothing on the `http_security` path sets either signal today
 * (`grep -c 'controlPresent\|recordPresent' packages/dns-checks/src/checks/check-http-security.ts src/tools/check-http-security.ts`
 * → 0) — but it is the same two-argument rebuild, so it is closed the same way.
 * The score/passed/checkStatus overrides stay: a heuristic attribution must not
 * re-derive the category score.
 */
function appendCdnFinding(httpResult: CheckResult, results: CheckResult[], cdnFinding: Finding): CheckResult[] {
	const updated = rebuildPreservingSignals(httpResult, [...httpResult.findings, cdnFinding]);
	const merged: CheckResult = {
		...updated,
		score: httpResult.score,
		passed: httpResult.passed,
		checkStatus: httpResult.checkStatus,
	};
	return upsertCheckResult(results, merged);
}
