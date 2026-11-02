// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../../lib/scoring';
import { addCdnHeuristics } from './cdn-heuristics';
import { applyMailApplicability } from './mail-applicability';
import { addOutboundProviderInference } from './provider-inference';

// Existing import paths stay valid after the SQ-535 split.
export { fetchCertIssuerFromCertstream } from './cdn-heuristics';
export { mxDeclaresNoInboundMail } from './mail-applicability';

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
	/**
	 * `WEB_POSTURE_ENABLED` kill switch for scan_domain's NON-SCORING web posture section (US-16
	 * T10), parsed by `parseWebPostureEnabled`. `false` omits the section entirely (no web posture
	 * fetches, and the section is stripped from a cache hit); absent or `true` runs it.
	 */
	webPostureEnabled?: boolean;
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
	let results = await applyMailApplicability(domain, checkResults, runtimeOptions?.nonApexHost);

	results = await addCdnHeuristics(domain, results, {
		certstream: runtimeOptions?.certstream,
		certstreamAuthToken: runtimeOptions?.certstreamAuthToken,
	});

	return addOutboundProviderInference(results, runtimeOptions);
}
