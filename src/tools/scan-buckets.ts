// SPDX-License-Identifier: BUSL-1.1
/** Cloud-bucket discovery tools — thin fail-soft proxies over bv-recon's bucket-scanner. */
import { buildCheckResult, createFinding } from '../lib/scoring';
import { markUnmeasured, stripReservedMarkers } from '../lib/unmeasured-result';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import {
	callReconBucketScanStart,
	callReconBucketScanStatus,
	callReconBucketFindings,
	type ReconBinding,
	type ReconFailureReason,
	type BindingDegradationSink,
} from '../lib/recon-binding';
import { extractBrandName, getRegistrableDomain } from '../lib/public-suffix';

// F7 (OWASP LLM01): upstream bv-recon strings spread into finding metadata below
// are sanitized at the `createFinding` chokepoint (`@blackveil/dns-checks/scoring`,
// recursive string neutralization + length clamp). The former per-tool
// `sanitizeUpstreamObject`/`sanitizeUpstreamValue` opt-ins were removed as redundant
// — every value here flows through `createFinding(... metadata)`.

const CATEGORY = 'bucket_scan' as CheckCategory;

export interface ReconToolOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
	bucketScanKv?: KVNamespace;
	principalId?: string;
	onBindingDegradation?: BindingDegradationSink;
}

function unprovisioned(detail: string): CheckResult {
	return markUnmeasured(
		buildCheckResult(CATEGORY, [createFinding(CATEGORY, 'Bucket scanning unavailable', 'info', detail, { unprovisioned: true })]),
	);
}

/**
 * Nothing was read while the binding IS bound. Reporting that as "not provisioned in this
 * deployment" told an operator to configure a binding that is already bound (#695).
 *
 * `marker` separates the two unmeasured-but-bound cases, which must not be conflated:
 * `upstreamUnavailable` = the service failed us (credential refused, non-2xx, schema mismatch,
 * fetch threw); `upstreamNotFound` = the service answered normally with a definitive 404 and the
 * id simply does not exist. Both withhold the verdict; only the first claims an outage, and
 * claiming one that did not happen is the same class of dishonesty #695 was about.
 *
 * `partial: true` keeps the transient state out of the registry cache (`(r) => !r.partial`), so
 * the next poll self-heals; the structural-absence path (`unprovisioned`) deliberately does NOT
 * set it — a permanent deployment fact gains nothing from cache suppression.
 */
function upstreamUnmeasured(
	marker: 'upstreamUnavailable' | 'upstreamNotFound',
	title: string,
	detail: string,
	meta: Record<string, unknown> = {},
): CheckResult {
	return {
		...markUnmeasured(buildCheckResult(CATEGORY, [createFinding(CATEGORY, title, 'info', detail, { ...meta, [marker]: true })])),
		partial: true,
	};
}

/** Prose for each distinguishable recon-failure class. See `reconFailureResult`. */
interface ReconFailureProse {
	/** `unbound` — no BV_RECON binding in this deployment. Permanent, structural. */
	unbound: string;
	/** `not_found` — upstream answered a definitive 404. A data miss, NOT a service failure. */
	notFound: { title: string; detail: string };
	/** `unauthorized` | `upstream_status` | `malformed` | `transport` — the recon service failed us. */
	unavailable: { title: string; detail: string };
}

/**
 * Map a `ReconOutcome` failure onto the honest unmeasured result for it.
 *
 * `callRecon*` no longer collapses its failure modes into a single `null` — it returns a
 * discriminated `ReconOutcome`, so this file can finally tell "this deployment has no bucket
 * scanner" from "that scan id does not exist" from "the recon service is down", and say so.
 * Only the first is a deployment fact (`unprovisioned`, cacheable); the other two are transient
 * and `partial: true`, and carry DIFFERENT markers (`upstreamNotFound` vs `upstreamUnavailable`)
 * as well as different prose — a 404 must NOT be narrated as an upstream failure, and an upstream
 * failure must no longer hedge "…or the id is unknown".
 *
 * `reconFailureReason` (and `reconUpstreamStatus`) are stamped into finding metadata for operator
 * visibility and analytics greppability. Both are LOCALLY derived — never upstream-controlled —
 * and neither collides with the reserved marker vocabulary in `lib/unmeasured-result.ts`.
 */
function reconFailureResult(
	failure: { reason: ReconFailureReason; status?: number },
	prose: ReconFailureProse,
	meta: Record<string, unknown> = {},
): CheckResult {
	if (failure.reason === 'unbound') return unprovisioned(prose.unbound);
	const notFound = failure.reason === 'not_found';
	const { title, detail } = notFound ? prose.notFound : prose.unavailable;
	return upstreamUnmeasured(notFound ? 'upstreamNotFound' : 'upstreamUnavailable', title, detail, {
		...meta,
		reconFailureReason: failure.reason,
		...(failure.status !== undefined ? { reconUpstreamStatus: failure.status } : {}),
	});
}

interface BucketScanScope {
	target?: string;
	providers?: string[];
	owner?: string;
}

interface BucketScanFindingArgs extends BucketScanScope {
	scanId: string;
}

interface TargetScopeTokens {
	substring: string[];
	segment: string[];
}

const BUCKET_SCAN_SCOPE_TTL_SECONDS = 24 * 60 * 60;

const PROVIDER_ALIASES: Record<string, string[]> = {
	aws: ['aws', 's3', 'aws_s3', 'amazon_s3'],
	gcp: ['gcp', 'gcp_storage', 'google', 'google_cloud_storage'],
	azure: ['azure', 'azure_blob'],
	alibaba: ['alibaba', 'alibaba_oss'],
	digitalocean: ['digitalocean', 'digitalocean_spaces', 'do_spaces'],
};

// Per-row cap on the bucket array spread into finding metadata (the MCP
// `structuredContent` channel). Mirrors the OSINT path's `REPORT_MAX_FINDINGS`
// so a huge upstream payload can't blow up structured output. The human-readable
// `detail` string is independently clamped to 800 chars.
const BUCKET_FINDINGS_MAX = 200;

// scanId is already Zod-bounded (max 128) and only ever used as a KV key suffix,
// so this is belt-and-suspenders: KV keys must stay to a conservative charset.
const SAFE_SCAN_ID = /^[A-Za-z0-9._:-]+$/;

function scopeKey(scanId: string): string {
	return `bucket-scan-scope:${scanId}`;
}

function normalizeTarget(target: string | undefined): string | undefined {
	if (!target) return undefined;
	let value = target.trim().toLowerCase();
	value = value.replace(/^https?:\/\//, '').split('/')[0] ?? value;
	value = value.replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
	return value || undefined;
}

function targetTokens(target: string | undefined): TargetScopeTokens {
	const normalized = normalizeTarget(target);
	if (!normalized) return { substring: [], segment: [] };

	// P3-1/P3-3: derive the registrable-domain org label via the PSL-backed
	// (tldts) helper instead of a hand-rolled suffix set, so a multi-label
	// subdomain like `sub.deep.acme.com` yields the org token `acme` (not
	// `sub`/`deep`/`acme`, which over-kept unrelated buckets such as `sub-prod`).
	// `extractBrandName` is `domainWithoutSuffix`; fall back to the bare normalized
	// host when the input isn't a PSL-resolvable domain (fail-open).
	const brand = extractBrandName(normalized);
	const registrable = getRegistrableDomain(normalized);
	const core = brand && brand.length > 0 ? brand : normalized;

	const substring = new Set<string>();
	const segment = new Set<string>();

	// P3-2: the match token is the suffix-stripped org label, not the full host —
	// so a public suffix (`.com`, `.test`) is no longer dead-weight in the token
	// (`acme.com` matches on `acme`, not `acmecom`).
	const coreCompact = core.replace(/[^a-z0-9]/g, '');
	if (coreCompact.length >= 3) {
		substring.add(coreCompact);
	} else if (coreCompact.length > 0) {
		// Fail-open for very short org labels (e.g. `x.test`): a 1–2 char token is
		// weak scope, so widen to the registrable-domain compact (org + suffix) to
		// avoid wrongly dropping in-scope buckets named after the full host.
		segment.add(coreCompact);
		const registrableCompact = (registrable ?? normalized).replace(/[^a-z0-9]/g, '');
		if (registrableCompact.length >= 3) substring.add(registrableCompact);
	}

	for (const label of core.split(/[^a-z0-9]+/).filter(Boolean)) {
		if (label.length >= 3) substring.add(label);
		else segment.add(label);
	}
	return { substring: [...substring], segment: [...segment] };
}

function hasTargetScope(tokens: TargetScopeTokens): boolean {
	return tokens.substring.length > 0 || tokens.segment.length > 0;
}

function normalizeProvider(provider: string | undefined): string | undefined {
	if (!provider) return undefined;
	return (
		provider
			.toLowerCase()
			.trim()
			.replace(/[^a-z0-9]+/g, '_')
			.replace(/^_+|_+$/g, '') || undefined
	);
}

function providerAllowed(provider: unknown, requestedProviders: string[] | undefined): boolean {
	if (!requestedProviders?.length) return true;
	if (typeof provider !== 'string') return true;
	const actual = normalizeProvider(provider);
	if (!actual) return true;
	return requestedProviders.some((requested) => {
		const normalized = normalizeProvider(requested);
		if (!normalized) return false;
		const aliases = PROVIDER_ALIASES[normalized] ?? [normalized];
		return aliases.some((alias) => actual === alias || actual.startsWith(`${alias}_`) || alias.startsWith(`${actual}_`));
	});
}

function bucketFindingName(finding: Record<string, unknown>): string {
	for (const key of ['bucketName', 'bucket', 'name', 'containerName']) {
		const value = finding[key];
		if (typeof value === 'string') return value.toLowerCase();
	}
	const endpoint = finding.endpoint;
	return typeof endpoint === 'string' ? endpoint.toLowerCase() : '';
}

function findingInTargetScope(finding: Record<string, unknown>, tokens: TargetScopeTokens): boolean {
	if (!hasTargetScope(tokens)) return true;
	const haystack = `${bucketFindingName(finding)} ${typeof finding.endpoint === 'string' ? finding.endpoint.toLowerCase() : ''}`;
	if (tokens.substring.some((token) => haystack.includes(token))) return true;
	const segments = new Set(haystack.split(/[^a-z0-9]+/).filter(Boolean));
	return tokens.segment.some((token) => segments.has(token));
}

function notOwned(id: string): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'Bucket scan not available', 'info', `Bucket scan ${id} is not owned by this principal.`, {
			notOwned: true,
			scanId: id,
		}),
	]) as CheckResult;
}

async function rememberBucketScanScope(scanId: string | undefined, scope: BucketScanScope, kv: KVNamespace | undefined): Promise<void> {
	if (!scanId || !kv || !SAFE_SCAN_ID.test(scanId)) return;
	const target = normalizeTarget(scope.target);
	if (!target && !scope.providers?.length && !scope.owner) return;
	await kv
		.put(scopeKey(scanId), JSON.stringify({ target, providers: scope.providers, owner: scope.owner }), {
			expirationTtl: BUCKET_SCAN_SCOPE_TTL_SECONDS,
		})
		.catch(() => undefined);
}

async function loadBucketScanScope(scanId: string | undefined, kv: KVNamespace | undefined): Promise<BucketScanScope> {
	if (!scanId || !kv || !SAFE_SCAN_ID.test(scanId)) return {};
	const raw = await kv.get(scopeKey(scanId)).catch(() => null);
	if (!raw) return {};
	try {
		const parsed = JSON.parse(raw) as BucketScanScope;
		return {
			target: normalizeTarget(parsed.target),
			providers: Array.isArray(parsed.providers) ? parsed.providers : undefined,
			owner: typeof parsed.owner === 'string' ? parsed.owner : undefined,
		};
	} catch {
		return {};
	}
}

function ownerMismatch(scope: BucketScanScope, caller: string | undefined): boolean {
	return Boolean(scope.owner && scope.owner !== caller);
}

function filterBucketPayload(payload: Record<string, unknown>, scope: BucketScanScope): Record<string, unknown> {
	const targetScope = targetTokens(scope.target);
	const arrayKey = Array.isArray(payload.data) ? 'data' : Array.isArray(payload.findings) ? 'findings' : undefined;
	if (!arrayKey || (!hasTargetScope(targetScope) && !scope.providers?.length)) return payload;
	const rows = payload[arrayKey] as unknown[];
	const kept: unknown[] = [];
	const filteredSamples: string[] = [];
	for (const row of rows) {
		if (!row || typeof row !== 'object' || Array.isArray(row)) {
			kept.push(row);
			continue;
		}
		const finding = row as Record<string, unknown>;
		if (findingInTargetScope(finding, targetScope) && providerAllowed(finding.provider, scope.providers)) {
			kept.push(row);
			continue;
		}
		if (filteredSamples.length < 5) filteredSamples.push(bucketFindingName(finding) || '(unnamed bucket)');
	}
	const filteredCount = rows.length - kept.length;
	// P3: cap the in-scope array spread into structured metadata (mirrors the OSINT
	// REPORT_MAX_FINDINGS=100 path). `count` stays the true in-scope total; the
	// emitted array is the (possibly truncated) prefix. Markers signal truncation.
	const keptTotal = kept.length;
	const keptTruncated = keptTotal > BUCKET_FINDINGS_MAX;
	const emitted = keptTruncated ? kept.slice(0, BUCKET_FINDINGS_MAX) : kept;
	if (filteredCount <= 0 && !keptTruncated) return payload;
	return {
		...payload,
		[arrayKey]: emitted,
		// In-scope total (not the possibly-truncated emitted length) so downstream
		// callers see the real count regardless of the structured-output cap.
		// Preserve prior behavior: only override `count` when upstream supplied one.
		count: typeof payload.count === 'number' ? keptTotal : payload.count,
		originalCount: typeof payload.count === 'number' ? payload.count : rows.length,
		filteredOutOfScopeCount: filteredCount,
		filteredOutOfScopeSamples: filteredSamples,
		...(keptTruncated ? { keptTruncated: true, keptCap: BUCKET_FINDINGS_MAX, keptTotal } : {}),
		targetScope: scope.target,
		providerScope: scope.providers,
	};
}

export async function scanBucketsStart(
	args: { target: string; providers?: string[] },
	options: ReconToolOptions = {},
): Promise<CheckResult> {
	const started = await callReconBucketScanStart(
		options.reconBinding,
		options.reconAuthToken,
		{ target: args.target, providers: args.providers },
		undefined,
		options.onBindingDegradation,
	);
	if (!started.ok)
		return reconFailureResult(started, {
			unbound: `Bucket discovery is not provisioned in this deployment for ${args.target}.`,
			notFound: {
				title: 'Bucket scan was not started',
				detail: `The recon service has no bucket-scan trigger for this request (HTTP 404), so no scan was started for ${args.target}. Nothing was scanned.`,
			},
			unavailable: {
				title: 'Bucket scan could not be started',
				detail: `The recon service did not start a bucket scan for ${args.target}. Nothing was scanned — retry, and if it persists this is a recon-service problem, not a result.`,
			},
		});
	const start = started.data;
	await rememberBucketScanScope(start.scanId, { ...args, owner: options.principalId }, options.bucketScanKv);
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			'Bucket scan started',
			'info',
			`Bucket discovery started for ${args.target} (scanId ${start.scanId}). Poll with scan_buckets_status.`,
			{
				...stripReservedMarkers(start),
				scanId: start.scanId,
				status: start.status ?? 'running',
				pollWith: 'scan_buckets_status',
			},
		),
	]) as CheckResult;
}

export async function scanBucketsStatus(args: { scanId: string }, options: ReconToolOptions = {}): Promise<CheckResult> {
	const scope = await loadBucketScanScope(args.scanId, options.bucketScanKv);
	if (ownerMismatch(scope, options.principalId)) return notOwned(args.scanId);
	const s = await callReconBucketScanStatus(
		options.reconBinding,
		options.reconAuthToken,
		args.scanId,
		undefined,
		options.onBindingDegradation,
	);
	if (!s.ok)
		return reconFailureResult(
			s,
			{
				unbound: `Bucket scanning is not provisioned in this deployment (scan ${args.scanId}).`,
				notFound: {
					title: 'Bucket scan status not available yet',
					detail: `The recon service has no record of bucket scan ${args.scanId} — the scan id is unknown or has expired, or it was only just started and is not registered yet. The recon service answered normally; this is not a service failure. Nothing was read about the scan's findings.`,
				},
				unavailable: {
					title: 'Bucket scan status could not be retrieved',
					detail: `The recon service did not return a usable status for bucket scan ${args.scanId}. Nothing was read about the scan's findings.`,
				},
			},
			{ scanId: args.scanId },
		);
	const status = s.data;
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Bucket scan ${args.scanId}`, 'info', JSON.stringify(status).slice(0, 800), {
			// F7: opaque upstream payload sanitized at the createFinding chokepoint. Reserved
			// unmeasured/refusal markers are stripped so upstream cannot write our control channel.
			...stripReservedMarkers(status),
			...(scope.target ? { targetScope: scope.target } : {}),
			...(scope.providers?.length ? { providerScope: scope.providers } : {}),
			summary: true,
			scanId: args.scanId, // caller input (already validated) — safe
		}),
	]) as CheckResult;
}

export async function scanBucketsFindings(args: BucketScanFindingArgs, options: ReconToolOptions = {}): Promise<CheckResult> {
	const rememberedScope = await loadBucketScanScope(args.scanId, options.bucketScanKv);
	if (ownerMismatch(rememberedScope, options.principalId)) return notOwned(args.scanId);
	const f = await callReconBucketFindings(
		options.reconBinding,
		options.reconAuthToken,
		args.scanId,
		undefined,
		options.onBindingDegradation,
	);
	if (!f.ok)
		return reconFailureResult(
			f,
			{
				unbound: 'Bucket scanning is not provisioned in this deployment.',
				notFound: {
					title: 'Bucket findings not available yet',
					detail: `The recon service has no findings recorded for bucket scan ${args.scanId} — the scan id is unknown or has expired, or results are not ready yet; poll scan_buckets_status. The recon service answered normally; this is not a service failure. This is NOT a report that no exposed buckets exist.`,
				},
				unavailable: {
					title: 'Bucket findings could not be retrieved',
					detail: `The recon service did not return usable findings for bucket scan ${args.scanId}. Nothing was read. This is NOT a report that no exposed buckets exist.`,
				},
			},
			{ scanId: args.scanId },
		);
	const target = normalizeTarget(args.target) ?? rememberedScope.target;
	const providers = args.providers ?? rememberedScope.providers;
	const filtered = filterBucketPayload(f.data, { target, providers });
	const filteredCount = typeof filtered.filteredOutOfScopeCount === 'number' ? filtered.filteredOutOfScopeCount : 0;
	const detailPrefix = filteredCount > 0 ? `Bucket findings filtered ${filteredCount} out-of-scope upstream candidate(s). ` : '';
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'Bucket findings', 'info', `${detailPrefix}${JSON.stringify(filtered).slice(0, 800)}`, {
			// F7 + reserved-marker strip — see scanBucketsStatus above.
			...stripReservedMarkers(filtered),
			summary: true,
		}),
	]) as CheckResult;
}
