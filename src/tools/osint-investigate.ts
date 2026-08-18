// SPDX-License-Identifier: BUSL-1.1
/** OSINT investigation tools — thin fail-soft proxies over bv-recon osint-worker workflows. */
import { buildCheckResult, createFinding } from '../lib/scoring';
import { markUnmeasured } from '../lib/unmeasured-result';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import {
	callReconInvestigateStart,
	callReconInvestigationStatus,
	callReconInvestigationReport,
	type ReconBinding,
	type ReconFailureReason,
	type ReconInvestigationType,
	type BindingDegradationSink,
} from '../lib/recon-binding';

const CATEGORY = 'osint_investigation' as CheckCategory;

export interface ReconToolOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
	reconJobKv?: KVNamespace;
	principalId?: string;
	onBindingDegradation?: BindingDegradationSink;
}

function unprovisioned(detail: string): CheckResult {
	return markUnmeasured(
		buildCheckResult(CATEGORY, [createFinding(CATEGORY, 'OSINT investigation unavailable', 'info', detail, { unprovisioned: true })]),
	);
}

/**
 * Shared body of the two TRANSIENT unmeasured outcomes below (`notFound` and
 * `upstreamUnavailable`).
 *
 * Both stamp the `upstreamUnavailable` marker because that is the unmeasured-availability
 * vocabulary owned by `src/lib/unmeasured-result.ts`, and it is what makes `markUnmeasured` set
 * `checkStatus: 'error'` so no verdict is reported for a lane nothing was read from. The two are
 * told apart by `reconFailureReason` — ordinary metadata, greppable in a structured response and
 * in analytics — NOT by a new marker key: the marker set is that module's SSOT and is scope-
 * enforced by `test/audits/unmeasured-marker-scope.audit.test.ts`.
 *
 * `partial: true` is deliberate and load-bearing here (and deliberately ABSENT on the
 * structural-absence path `unprovisioned()`): the registry cache predicate is `(r) => !r.partial`
 * (`src/handlers/tools.ts`), so this keeps a transient condition out of the cache and lets the
 * next poll self-heal. A permanent deployment fact would gain nothing from cache suppression and
 * would just pay the service-binding round-trip on every call.
 */
function transientUnmeasured(
	marker: 'upstreamUnavailable' | 'upstreamNotFound',
	title: string,
	detail: string,
	meta: Record<string, unknown>,
): CheckResult {
	return {
		...markUnmeasured(buildCheckResult(CATEGORY, [createFinding(CATEGORY, title, 'info', detail, { [marker]: true, ...meta })])),
		partial: true,
	};
}

/**
 * The recon service answered DEFINITIVELY 404: the id is unknown or expired, or the caller raced
 * its own `*_start` and the investigation is not registered yet.
 *
 * Nothing was read, so the verdict is still withheld — but this is NOT an outage and must not be
 * reported as one, which is why it carries the distinct `upstreamNotFound` marker rather than
 * `upstreamUnavailable` (both are unmeasured; only one claims the service failed). The distinction is available because `callRecon*` returns a discriminated
 * `ReconOutcome` (`src/lib/recon-binding.ts`) instead of the former single `null`; upstream treats
 * a 404 as a data miss and stays silent rather than emitting a false binding degradation.
 *
 * Stays `partial: true` for the race case that `isRetryableReconFailure` classes retryable: an id
 * that 404s now may exist moments later, so this result must not be cached.
 */
function notFound(title: string, detail: string, meta: Record<string, unknown> = {}): CheckResult {
	return transientUnmeasured('upstreamNotFound', title, detail, { reconFailureReason: 'not_found', ...meta });
}

/**
 * The binding IS bound and the call still yielded no data: the credential was rejected
 * (`unauthorized`), the upstream returned some other non-2xx (`upstream_status`), a 2xx body
 * failed schema validation (`malformed`), or the fetch threw (`transport`).
 *
 * Those four are exactly what remains once `unbound` and `not_found` are excluded by the `reason`
 * type — they are routed to `unprovisioned()` and `notFound()` — so this prose no longer has to
 * hedge about the id being unknown or expired. That hedge existed only because `callRecon*` used
 * to collapse every condition into one `null`; it does not any more.
 *
 * Kept DISTINCT from `unprovisioned()` because the two states are opposites operationally:
 * unprovisioned is a permanent, structural fact about this deployment, while this is an upstream
 * condition that may resolve on the next poll. Reporting an outage as "not provisioned in this
 * deployment" — which is what this path did until #695 — tells an operator to go configure a
 * binding that is already bound.
 *
 * The specific `reason` rides along in metadata so an operator reading a structured response can
 * see WHY without a log dive: `unauthorized` means fix the credential, `malformed` means the
 * bv-recon response contract drifted, `transport`/`upstream_status` mean wait and re-poll.
 */
function upstreamUnavailable(
	reason: Exclude<ReconFailureReason, 'unbound' | 'not_found'>,
	title: string,
	detail: string,
	meta: Record<string, unknown> = {},
): CheckResult {
	return transientUnmeasured('upstreamUnavailable', title, detail, { reconFailureReason: reason, ...meta });
}

/**
 * Per-call-site prose for each way a recon call can come back without data. Written per call site
 * because "no such id" reads differently on a start (the route does not exist) than on a poll (the
 * investigation does not exist).
 */
interface UnavailableProse {
	/** No BV_RECON binding at all — a permanent fact about this deployment. */
	unbound: string;
	/** Upstream said 404 — a data miss, not a failure. */
	notFound: string;
	/** Bound, but the call failed: auth, non-2xx, contract drift, or transport. */
	upstream: string;
}

/**
 * The single mapping from a `ReconFailureReason` to the result shape that is TRUE for it, so all
 * three tools stay in lockstep instead of each re-deriving the distinction inline.
 */
function reconUnavailable(
	reason: ReconFailureReason,
	title: string,
	prose: UnavailableProse,
	meta: Record<string, unknown> = {},
): CheckResult {
	if (reason === 'unbound') return unprovisioned(prose.unbound);
	if (reason === 'not_found') return notFound(title, prose.notFound, meta);
	return upstreamUnavailable(reason, title, prose.upstream, meta);
}

const OSINT_OWNER_TTL_SECONDS = 24 * 60 * 60;
const SAFE_INVESTIGATION_ID = /^[A-Za-z0-9._:-]+$/;

function ownerKey(id: string): string {
	return `osint-investigation-owner:${id}`;
}

function notOwned(id: string): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'OSINT investigation not available', 'info', `OSINT investigation ${id} is not owned by this principal.`, {
			notOwned: true,
			investigationId: id,
		}),
	]) as CheckResult;
}

async function rememberInvestigationOwner(id: string | undefined, options: ReconToolOptions): Promise<void> {
	if (!id || !options.reconJobKv || !options.principalId || !SAFE_INVESTIGATION_ID.test(id)) return;
	await options.reconJobKv.put(ownerKey(id), options.principalId, { expirationTtl: OSINT_OWNER_TTL_SECONDS }).catch(() => undefined);
}

async function investigationOwnerMismatch(id: string, options: ReconToolOptions): Promise<boolean> {
	if (!options.reconJobKv || !SAFE_INVESTIGATION_ID.test(id)) return false;
	const owner = await options.reconJobKv.get(ownerKey(id)).catch(() => null);
	return Boolean(owner && owner !== options.principalId);
}

export async function osintInvestigateStart(
	type: ReconInvestigationType,
	query: string,
	options: ReconToolOptions = {},
): Promise<CheckResult> {
	const outcome = await callReconInvestigateStart(
		options.reconBinding,
		options.reconAuthToken,
		type,
		query,
		undefined,
		undefined,
		options.onBindingDegradation,
	);
	if (!outcome.ok)
		return reconUnavailable(
			outcome.reason,
			`OSINT ${type} investigation could not be started`,
			{
				unbound: `OSINT ${type} investigation is not provisioned in this deployment for ${query}.`,
				// A 404 on the START route cannot mean "unknown id" — no id exists yet. It means the
				// recon service does not expose this investigation type (route/contract drift).
				notFound: `The recon service has no ${type} investigation endpoint, so no investigation was started for ${query}.`,
				upstream: `The recon service did not start a ${type} investigation for ${query}. Nothing was read and no investigation exists — retry, or check the operator credential if this persists.`,
			},
			{ type },
		);
	const started = outcome.data;
	await rememberInvestigationOwner(started.investigationId, options);
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			`OSINT ${type} investigation started`,
			'info',
			`Started ${type} investigation for ${query} (id ${started.investigationId}). Poll with osint_investigation_status.`,
			{
				investigationId: started.investigationId,
				type,
				status: started.status ?? 'running',
				pollWith: 'osint_investigation_status',
			},
		),
	]) as CheckResult;
}

export const osintInvestigateDomainStart = (q: string, o?: ReconToolOptions) => osintInvestigateStart('domain', q, o);
export const osintInvestigateInfrastructureStart = (q: string, o?: ReconToolOptions) => osintInvestigateStart('deep_infrastructure', q, o);
export const osintInvestigateSupplyChainStart = (q: string, o?: ReconToolOptions) => osintInvestigateStart('supply_chain', q, o);

/**
 * Lightweight progress/summary fields surfaced by `osint_investigation_status`.
 * Deliberately EXCLUDES the heavy `findings[]` array — that belongs to the
 * report endpoint. Inlining it here blew past the MCP token cap (53 KB+).
 */
const STATUS_META_KEYS = [
	'id',
	'type',
	'query',
	'status',
	'workflowId',
	'progress',
	'totalChecks',
	'completedChecks',
	'foundCount',
	'aiAnalysis',
	'reportR2Key',
	'options',
	'createdAt',
	'updatedAt',
	'completedAt',
] as const;

/** Per-finding fields kept in the report. Drops the multi-KB `rawData` blob (and `evidenceR2Key`). */
const FINDING_KEEP_KEYS = [
	'type',
	'severity',
	'title',
	'details',
	'confidence',
	'platform',
	'platformCategory',
	'url',
	'createdAt',
] as const;

/** Hard cap on findings returned in a single report response, to stay under the MCP token cap. */
const REPORT_MAX_FINDINGS = 100;

// These projections handle the TOKEN-CAP concern (allowlisting which upstream
// keys survive + truncating the findings[] array) — NOT injection. F7 string
// neutralization + length clamp + depth-bounded recursion of every surviving
// upstream string now happens at the `createFinding` chokepoint
// (`@blackveil/dns-checks/scoring`), so the former per-value `sanitizeUpstreamValue`
// wrapping here was removed as redundant. The key allowlisting below MUST stay.

function projectStatusMeta(s: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const k of STATUS_META_KEYS) if (k in s) out[k] = s[k];
	return out;
}

function shapeFinding(f: unknown): Record<string, unknown> {
	const src = (f && typeof f === 'object' ? f : {}) as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const k of FINDING_KEEP_KEYS) if (k in src) out[k] = src[k];
	return out;
}

function projectReportMeta(r: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	// Upstream summary TEXT lives under `investigationSummary`; the bare `summary`
	// key is reserved as the codebase-wide "summary finding" boolean sentinel.
	if ('summary' in r) out.investigationSummary = r.summary;
	if ('total' in r) out.total = r.total;
	const raw = Array.isArray(r.findings) ? r.findings : [];
	out.findings = raw.slice(0, REPORT_MAX_FINDINGS).map(shapeFinding);
	if (raw.length > REPORT_MAX_FINDINGS) {
		out.findingsTruncated = true;
		out.findingsTotal = raw.length;
	}
	return out;
}

function shortText(s: string, max: number): string {
	return s.length > max ? s.slice(0, max) : s;
}

export async function osintInvestigationStatus(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	if (await investigationOwnerMismatch(id, options)) return notOwned(id);
	const outcome = await callReconInvestigationStatus(
		options.reconBinding,
		options.reconAuthToken,
		id,
		undefined,
		options.onBindingDegradation,
	);
	if (!outcome.ok)
		return reconUnavailable(
			outcome.reason,
			'OSINT investigation status could not be retrieved',
			{
				unbound: `OSINT investigation status is not provisioned in this deployment (investigation ${id}).`,
				notFound: `The recon service has no investigation ${id} — the id is unknown or expired, or it was started moments ago and is not registered yet. Nothing was read; re-poll if you have just started it.`,
				upstream: `The recon service did not return a usable status for investigation ${id}. This is not a statement about the investigation's findings — nothing was read.`,
			},
			{ investigationId: id },
		);
	const s = outcome.data;
	const status = typeof s.status === 'string' ? s.status : 'unknown';
	const parts = [`status=${status}`];
	if (typeof s.completedChecks === 'number' && typeof s.totalChecks === 'number')
		parts.push(`${s.completedChecks}/${s.totalChecks} checks`);
	if (typeof s.foundCount === 'number') parts.push(`${s.foundCount} found`);
	if (typeof s.summary === 'string' && s.summary.trim()) parts.push(s.summary.trim());
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id}`, 'info', shortText(parts.join(' · '), 800), {
			...projectStatusMeta(s),
			...(typeof s.summary === 'string' ? { investigationSummary: s.summary } : {}),
			summary: true,
			investigationId: id,
		}),
	]) as CheckResult;
}

export async function osintInvestigationReport(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	if (await investigationOwnerMismatch(id, options)) return notOwned(id);
	const outcome = await callReconInvestigationReport(
		options.reconBinding,
		options.reconAuthToken,
		id,
		undefined,
		options.onBindingDegradation,
	);
	if (!outcome.ok)
		return reconUnavailable(
			outcome.reason,
			'OSINT investigation report could not be retrieved',
			{
				unbound: `OSINT investigation reports are not provisioned in this deployment (investigation ${id}).`,
				notFound: `The recon service has no report for investigation ${id} — the id is unknown or expired, or no report has been produced yet. Poll osint_investigation_status. No findings were read.`,
				upstream: `The recon service did not return a usable report for investigation ${id}. The investigation may still be running — poll osint_investigation_status and retry. No findings were read.`,
			},
			{ investigationId: id },
		);
	const r = outcome.data;
	const total = typeof r.total === 'number' ? r.total : Array.isArray(r.findings) ? r.findings.length : 0;
	const summary = typeof r.summary === 'string' ? r.summary.trim() : '';
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id} report`, 'info', shortText(`${total} findings.${summary ? ` ${summary}` : ''}`, 1200), {
			...projectReportMeta(r),
			summary: true,
			investigationId: id,
		}),
	]) as CheckResult;
}
