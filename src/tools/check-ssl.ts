// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Operator-only enrichment: when a `tlsProbeBinding` is provided (via the BV_TLS_PROBE
 * service binding), the result is enriched with negotiated-TLS-version data. BSL
 * self-hosts without the binding receive the unmodified base result.
 */

import { checkSSL, withRobotsGate } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { callTlsProbe, mergeTlsFinding } from '../lib/tls-probe-binding';
import { enrichWithCertificateMetadata } from '../lib/cert-metadata-enrich';
import type { TlsProbeBinding, BindingDegradationSink } from '../lib/tls-probe-binding';
import { withAbortSignal } from '../lib/abort-signal';
import { withRobotsFetchMemo, type RobotsFetchMemo } from '../lib/robots-memo';
import { createFetchBudget } from '../lib/fetch-budget';
import { createRobotsProvenance } from '../lib/robots-provenance';

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP→HTTPS redirect.
 *
 * @param domain - The domain to check.
 * @param tlsProbeOptions - Optional operator-only TLS-version enrichment options.
 *   `tlsProbeBinding`: the BV_TLS_PROBE service binding (absent on all BSL self-hosts).
 *   `tlsProbeAuthToken`: bearer token forwarded to the probe endpoint.
 *   Omitting the binding (or passing an empty object) returns the result unchanged — fail-soft.
 */
export async function checkSsl(
	domain: string,
	tlsProbeOptions: {
		tlsProbeBinding?: TlsProbeBinding;
		tlsProbeAuthToken?: string;
		onBindingDegradation?: BindingDegradationSink;
		/**
		 * Optional caller-supplied abort signal (R7). When provided, it is composed
		 * with the package's own per-fetch `AbortSignal.timeout` so a scan-/per-check
		 * timeout ABORTS the in-flight HTTPS subrequests rather than merely abandoning
		 * them — freeing the Cloudflare Workers subrequest budget. Absent (every direct
		 * `check_ssl` call) → byte-for-byte unchanged behaviour.
		 */
		signal?: AbortSignal;
		/**
		 * Optional per-scan robots.txt fetch memo (issue #641). When supplied,
		 * `https://<domain>/robots.txt` is fetched at most once across every check
		 * in the same scan that shares this memo (today: `ssl` + `http_security`,
		 * which target the SAME host) instead of once per check. Absent (every
		 * direct `check_ssl` call) → a private per-call gate, unchanged behaviour.
		 *
		 * Latency only: the gate still parses and applies the robots rules itself,
		 * so a disallow still throws `RobotsDisallowedError` and still excludes the
		 * category exactly as before.
		 */
		robotsMemo?: RobotsFetchMemo;
		/**
		 * Opt IN to certificate metadata (issuer / expiry / SANs) from Certificate
		 * Transparency. DEFAULT OFF, and deliberately so.
		 *
		 * Enrichment costs one extra subrequest to Certspotter's public API, whose
		 * free tier is ~100 requests/hour/egress-IP and is SHARED across everything
		 * this Worker does. `scan_domain` fans out 17 checks per call, so enriching
		 * there would spend that quota at scan volume — and an exhausted quota
		 * degrades to no metadata at all, for every caller.
		 *
		 * So only the DIRECT `check_ssl` tool turns this on: that is the tool whose
		 * description promises issuer and expiry, and it is called one domain at a
		 * time. `scan_domain`, `validate_fix`, and `simulate_attack_paths` leave it
		 * off — none of them surfaces the field, so the request would be pure cost.
		 *
		 * A caching layer in front of Certspotter is what would make this safe to
		 * turn on everywhere; there isn't one on this Worker today.
		 */
		certMetadata?: boolean;
		/**
		 * Total wall-clock this check's fetches may collectively consume (issue #641).
		 *
		 * `checkSSL` runs robots.txt (3s) → `https://` (4s) → `http://` (4s) strictly
		 * sequentially, so its worst case is 11s — structurally unable to finish inside
		 * `scan_domain`'s 8s per-check budget. When that happened the outer `safeCheck`
		 * killed the check and the whole `ssl` category was lost (`null`, excluded,
		 * −3–4 points) even though HTTPS/HSTS had already been measured; only the final
		 * redirect leg was outstanding.
		 *
		 * With a budget, each fetch is bounded by what the earlier ones left, so the
		 * check degrades by dropping its LAST probe instead of losing everything. The
		 * dropped leg emits no finding — `checkHttpRedirect` swallows a failed probe by
		 * design — so the effect is an absent `medium`, never a fabricated one.
		 *
		 * Absent (every direct `check_ssl` call) → unchanged behaviour.
		 */
		budgetMs?: number;
	} = {},
): Promise<CheckResult> {
	// Memo sits BENEATH the gate (and beneath the abort composition) so the gate's
	// own robots.txt fetch is what gets deduplicated, while parsing/rule selection
	// stay per-gate. No memo → `withRobotsFetchMemo` returns the function unchanged.
	// Budget sits INNERMOST of the three wrappers — which is what makes it meter
	// EVERY leg: the gate's own robots.txt fetch delegates down through it. That leg
	// is up to 3s of the 8s budget and is exactly the cost that pushed this check
	// over, so hoisting the budget outside `withRobotsGate` would stop metering the
	// most expensive one. Its clock still starts at wrapper CREATION, so the budget
	// is one absolute deadline shared by all three legs, not a per-fetch allowance.
	const budget = createFetchBudget(tlsProbeOptions.budgetMs);
	// Records which branch of the robots gate decided this invocation (issue #745) —
	// including the fail-open one, so a scored `ssl` category carries positive
	// evidence of WHY it was scored. Observation only: no finding, no score effect.
	const provenance = createRobotsProvenance(domain);
	const fetchFn = withRobotsGate(
		withRobotsFetchMemo(budget.wrap(withAbortSignal(fetch, tlsProbeOptions.signal)), tlsProbeOptions.robotsMemo),
		{ onRobotsResolution: provenance.onResolution },
	);
	// The TLS probe is launched HERE, alongside the HTTPS legs, not after them.
	// It needs only the domain — it never reads the fetch result — so running it
	// sequentially bought nothing and cost everything: its own fixed 8s timeout on
	// top of 7.25s of budgeted fetches, inside an 8s per-check kill. Concurrent, the
	// check's worst case is the MAX of the two rather than their SUM, and the probe
	// still yields its scoring-relevant finding on slow domains instead of being
	// squeezed out by whatever the fetches left. `budget.signal()` also caps it at
	// the shared deadline, so it can no longer outlive the budget on its own 8s clock.
	//
	// Fail-soft is preserved end to end: `callTlsProbe` returns null on any failure,
	// and the `.catch` is belt-and-braces so a launched-but-unawaited rejection can
	// never surface as an unhandled rejection if `checkSSL` throws first.
	const probePromise = tlsProbeOptions.tlsProbeBinding
		? callTlsProbe(tlsProbeOptions.tlsProbeBinding, tlsProbeOptions.tlsProbeAuthToken, domain, {
				telemetry: tlsProbeOptions.onBindingDegradation,
				signal: budget.signal(tlsProbeOptions.signal),
			}).catch(() => null)
		: null;
	const base = (await checkSSL(domain, fetchFn, { timeout: HTTPS_TIMEOUT_MS })) as CheckResult;
	// Certificate metadata (issuer / expiry / SANs) from Certificate Transparency.
	// NON-SCORING: attaches to `metadata`, never appends a Finding — a CT lookup
	// failing must not move a domain's grade.
	//
	// Deliberately NOT robots-gated: the request goes to Certspotter's public API,
	// not to the scanned domain, so the target's robots.txt has no authority over
	// it. It IS abort-composed, so a scan-/per-check timeout cancels the in-flight
	// CT subrequest rather than leaking it from the subrequest budget (R7).
	const result = tlsProbeOptions.certMetadata
		? await enrichWithCertificateMetadata(base, domain, budget.wrap(withAbortSignal(fetch, tlsProbeOptions.signal)))
		: base;
	// Operator-only TLS-version enrichment via the BV_TLS_PROBE service binding.
	// NOTE this one DOES affect scoring (it appends a High finding), unlike the
	// certificate-metadata enrichment above.
	// Fail-soft: absent binding (every BSL self-host) → result returned unchanged.
	// callTlsProbe returns null on any failure; mergeTlsFinding only ever appends a
	// High finding when the probe actively reports legacy TLS (≤1.1), never penalizes 1.2/1.3.
	if (!probePromise) return provenance.stamp(result);
	const probe = await probePromise;
	return provenance.stamp(probe ? mergeTlsFinding(result, probe) : result);
}
