// SPDX-License-Identifier: BUSL-1.1

/**
 * RDAP Lookup tool — Domain Registration Data.
 * Fetches domain registration data via RDAP (modern WHOIS replacement).
 * Uses only HTTP fetch (no DNS queries).
 */

import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

const CATEGORY = 'rdap' as CheckCategory;

/**
 * Wall-clock budget for the synchronous `rdap_lookup` tool path, threaded into
 * the orchestrator as the caller AbortSignal AND as `deadlineMs` so retry
 * sleeps + WHOIS follow-on calls clamp against the remaining budget instead of
 * stacking unbounded `Retry-After` waits (otherwise: 10s fetch + 15s server-
 * controlled Retry-After + 10s retry + 10s WHOIS ≈ 45s, well past the 28s
 * tool-call cap). Kept inside `TOOL_CALL_TIMEOUT_MS` so the tool settles
 * before the outer `Promise.race(__tool_timeout__)` fires.
 */
export const RDAP_LOOKUP_SYNC_BUDGET_MS = 24_000;

/** RDAP bootstrap URL (IANA). */
const IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/**
 * Hardcoded RDAP server fallbacks for common TLDs. Used when the IANA bootstrap
 * fetch is unavailable (cold start, network blip). Snapshot from IANA's
 * canonical bootstrap; rarely changes — the audit test in Phase 6 of the
 * registrar-coverage TDD plan pins the coverage list. URLs that change at the
 * registry level get corrected when IANA bootstrap comes back online.
 */
export const FALLBACK_RDAP_SERVERS: Record<string, string> = {
	// Verisign-operated
	com: 'https://rdap.verisign.com/com/v1/',
	net: 'https://rdap.verisign.com/net/v1/',
	// Public Interest Registry
	org: 'https://rdap.publicinterestregistry.org/rdap/',
	// Identity Digital (formerly Afilias / Donuts)
	info: 'https://rdap.identitydigital.services/rdap/',
	biz: 'https://rdap.nic.biz/',
	us: 'https://rdap.identitydigital.services/rdap/',
	tech: 'https://rdap.identitydigital.services/rdap/',
	online: 'https://rdap.identitydigital.services/rdap/',
	email: 'https://rdap.identitydigital.services/rdap/',
	global: 'https://rdap.identitydigital.services/rdap/',
	group: 'https://rdap.identitydigital.services/rdap/',
	life: 'https://rdap.identitydigital.services/rdap/',
	live: 'https://rdap.identitydigital.services/rdap/',
	media: 'https://rdap.identitydigital.services/rdap/',
	news: 'https://rdap.identitydigital.services/rdap/',
	services: 'https://rdap.identitydigital.services/rdap/',
	software: 'https://rdap.identitydigital.services/rdap/',
	solutions: 'https://rdap.identitydigital.services/rdap/',
	support: 'https://rdap.identitydigital.services/rdap/',
	systems: 'https://rdap.identitydigital.services/rdap/',
	technology: 'https://rdap.identitydigital.services/rdap/',
	tools: 'https://rdap.identitydigital.services/rdap/',
	// Identity Digital ccTLDs / TLD operators
	io: 'https://rdap.identitydigital.services/rdap/',
	ai: 'https://rdap.nic.ai/',
	sh: 'https://rdap.identitydigital.services/rdap/',
	// auDA
	au: 'https://rdap.cctld.au/rdap/',
	// Traficom
	fi: 'https://rdap.fi/rdap/rdap/',
	// .CO Internet
	co: 'https://rdap.nic.co/',
	// ME Registry
	me: 'https://rdap.nic.me/',
	// Google Registry — pubapi is the canonical RDAP endpoint; www.registry.google returns 404.
	app: 'https://pubapi.registry.google/rdap/',
	dev: 'https://pubapi.registry.google/rdap/',
	// XYZ.COM LLC
	xyz: 'https://rdap.nic.xyz/',
	// ccTLDs reachable via IANA bootstrap — hardcoded here as failsafe for when
	// the bootstrap fetch is negative-cached (transient data.iana.org outage).
	ca: 'https://rdap.ca.fury.ca/rdap/',
	cz: 'https://rdap.nic.cz/',
	fr: 'https://rdap.nic.fr/',
	in: 'https://rdap.nixiregistry.in/rdap/',
	nl: 'https://rdap.sidn.nl/',
	no: 'https://rdap.norid.no/',
	pl: 'https://rdap.dns.pl/',
	sg: 'https://rdap.sgnic.sg/rdap/',
	uk: 'https://rdap.nominet.uk/uk/',
};

/** TTL for a successful IANA bootstrap fetch (6h). */
const BOOTSTRAP_TTL_MS = 6 * 60 * 60 * 1000;

/** TTL for a failed bootstrap fetch (10s) — short so transient blips recover quickly. The hardcoded fallback map covers the common-TLD path during the negative-cache window. */
const BOOTSTRAP_FAILURE_TTL_MS = 10 * 1000;

/** Module-level bootstrap state (per isolate lifetime). */
let bootstrapState: { value: Record<string, string>; fetchedAt: number } | null = null;
let bootstrapFailure: { failedAt: number } | null = null;
/** In-flight bootstrap fetch — concurrent RDAP calls share a single IANA request. */
let bootstrapInFlight: Promise<Record<string, string>> | null = null;

/** Reset bootstrap cache — exported for test isolation. */
export function _resetBootstrapCache(): void {
	bootstrapState = null;
	bootstrapFailure = null;
	bootstrapInFlight = null;
}

/** Timeout for all outbound RDAP fetches (ms). */
const RDAP_TIMEOUT_MS = 10_000;
const RDAP_RETRYABLE_HTTP_STATUSES = new Set([429, 503, 504]);
const RDAP_RETRY_MAX_ATTEMPTS = 2;
const RDAP_RETRY_DEFAULT_DELAY_MS = 750;
const RDAP_RETRY_MAX_DELAY_MS = 2_000;

interface RdapEvent {
	eventAction: string;
	eventDate: string;
}

interface RdapVcardProperty {
	0: string; // property name
	1: Record<string, unknown>; // parameters
	2: string; // type
	3: unknown; // value
}

interface RdapEntity {
	objectClassName?: string;
	roles?: string[];
	publicIds?: Array<{ type?: string; identifier?: string }>;
	vcardArray?: ['vcard', RdapVcardProperty[]];
	entities?: RdapEntity[];
}

interface RdapDomainResponse {
	ldhName?: string;
	status?: string[];
	events?: RdapEvent[];
	entities?: RdapEntity[];
}

/**
 * Fetch and parse the IANA RDAP bootstrap file. Caches the result for
 * BOOTSTRAP_TTL_MS on success, BOOTSTRAP_FAILURE_TTL_MS on failure (so we don't
 * hammer IANA during an outage but recover quickly once it returns).
 * Returns a TLD → RDAP server URL map.
 */
async function fetchBootstrap(): Promise<Record<string, string>> {
	const now = Date.now();
	if (bootstrapState && now - bootstrapState.fetchedAt < BOOTSTRAP_TTL_MS) {
		return bootstrapState.value;
	}
	if (bootstrapFailure && now - bootstrapFailure.failedAt < BOOTSTRAP_FAILURE_TTL_MS) {
		return {};
	}
	if (bootstrapInFlight) {
		return bootstrapInFlight;
	}

	bootstrapInFlight = (async () => {
		try {
			const resp = await fetch(IANA_BOOTSTRAP_URL, {
				redirect: 'manual',
				signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
				headers: { Accept: 'application/json' },
			});
			if (!resp.ok) {
				bootstrapFailure = { failedAt: Date.now() };
				return {};
			}

			const data = (await resp.json()) as { services?: [string[], string[]][] };
			const map: Record<string, string> = {};

			if (Array.isArray(data.services)) {
				for (const [tlds, urls] of data.services) {
					if (!Array.isArray(tlds) || !Array.isArray(urls) || urls.length === 0) continue;
					const serverUrl = urls[0];
					for (const tld of tlds) {
						if (typeof tld === 'string' && typeof serverUrl === 'string') {
							map[tld.toLowerCase()] = serverUrl;
						}
					}
				}
			}

			bootstrapState = { value: map, fetchedAt: Date.now() };
			bootstrapFailure = null;
			return map;
		} catch {
			bootstrapFailure = { failedAt: Date.now() };
			return {};
		} finally {
			bootstrapInFlight = null;
		}
	})();
	return bootstrapInFlight;
}

/**
 * Resolve the RDAP server URL for a given TLD.
 * Tries IANA bootstrap first, then hardcoded fallbacks.
 */
async function resolveRdapServer(tld: string): Promise<string | null> {
	const normalizedTld = tld.toLowerCase();

	// Try bootstrap
	const bootstrap = await fetchBootstrap();
	if (bootstrap[normalizedTld]) return bootstrap[normalizedTld];

	// Fallback to hardcoded map
	return FALLBACK_RDAP_SERVERS[normalizedTld] ?? null;
}

/** Extract the full name from a vCard array for a given role. */
function extractVcardName(entity: RdapEntity): string | null {
	if (!entity.vcardArray || entity.vcardArray[0] !== 'vcard') return null;
	const properties = entity.vcardArray[1];
	if (!Array.isArray(properties)) return null;

	for (const prop of properties) {
		if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string') {
			return prop[3];
		}
	}
	for (const prop of properties) {
		if (!Array.isArray(prop) || prop[0] !== 'org') continue;
		const value = prop[3];
		if (typeof value === 'string' && value.trim().length > 0) return value.trim();
		if (Array.isArray(value)) {
			const joined = value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0).join(' ');
			if (joined.length > 0) return joined;
		}
	}
	return null;
}

/** Extract country from a vCard adr property. */
function extractVcardCountry(entity: RdapEntity): string | null {
	if (!entity.vcardArray || entity.vcardArray[0] !== 'vcard') return null;
	const properties = entity.vcardArray[1];
	if (!Array.isArray(properties)) return null;

	for (const prop of properties) {
		if (Array.isArray(prop) && prop[0] === 'adr') {
			const value = prop[3];
			if (Array.isArray(value) && value.length > 0) {
				const country = value[value.length - 1];
				return typeof country === 'string' && country.length > 0 ? country : null;
			}
		}
	}
	return null;
}

/** Find an entity with the given role. Searches top-level and nested entities. */
function findEntityByRole(entities: RdapEntity[] | undefined, role: string): RdapEntity | null {
	if (!Array.isArray(entities)) return null;
	for (const entity of entities) {
		if (Array.isArray(entity.roles) && entity.roles.includes(role)) {
			return entity;
		}
		// Search nested entities
		if (Array.isArray(entity.entities)) {
			const nested = findEntityByRole(entity.entities, role);
			if (nested) return nested;
		}
	}
	return null;
}

function extractRegistrarIanaId(entity: RdapEntity | null): string | null {
	if (!entity || !Array.isArray(entity.publicIds)) return null;
	for (const publicId of entity.publicIds) {
		if (
			typeof publicId.type === 'string' &&
			/^IANA Registrar ID$/i.test(publicId.type.trim()) &&
			typeof publicId.identifier === 'string' &&
			publicId.identifier.trim().length > 0
		) {
			return publicId.identifier.trim();
		}
	}
	return null;
}

function findEntityByRegistrarIanaId(entities: RdapEntity[] | undefined): RdapEntity | null {
	if (!Array.isArray(entities)) return null;
	for (const entity of entities) {
		if (extractRegistrarIanaId(entity)) return entity;
		if (Array.isArray(entity.entities)) {
			const nested = findEntityByRegistrarIanaId(entity.entities);
			if (nested) return nested;
		}
	}
	return null;
}

/**
 * Parse an HTTP `Retry-After` header into a sleep duration (ms), clamped both
 * by the orchestrator's internal `RDAP_RETRY_MAX_DELAY_MS` ceiling AND by the
 * remaining tool-call budget if `remainingBudgetMs` is supplied. The header
 * value is server-controlled — a misbehaving (or DoS-adversarial) RDAP server
 * can ship `Retry-After: 60`, which would otherwise eat the whole sync budget
 * on a single retry. Returning `0` here tells the caller to skip the sleep
 * and short-circuit retry attempts (the budget is exhausted anyway).
 */
function parseRetryAfterMs(value: string | null, remainingBudgetMs?: number): number {
	// If the caller passes a budget and it's already exhausted, don't sleep —
	// the next loop iteration would just abort on the composed signal anyway,
	// burning the entire `Retry-After` wait for nothing.
	if (typeof remainingBudgetMs === 'number' && remainingBudgetMs <= 0) return 0;

	const ceiling =
		typeof remainingBudgetMs === 'number'
			? Math.max(0, Math.min(RDAP_RETRY_MAX_DELAY_MS, remainingBudgetMs))
			: RDAP_RETRY_MAX_DELAY_MS;

	if (!value) return Math.min(RDAP_RETRY_DEFAULT_DELAY_MS, ceiling);
	const seconds = Number(value);
	if (Number.isFinite(seconds) && seconds >= 0) {
		return Math.min(seconds * 1000, ceiling);
	}
	const dateMs = Date.parse(value);
	if (Number.isFinite(dateMs)) {
		return Math.min(Math.max(dateMs - Date.now(), 0), ceiling);
	}
	return Math.min(RDAP_RETRY_DEFAULT_DELAY_MS, ceiling);
}

async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	if (ms <= 0) return;
	await new Promise<void>((resolve, reject) => {
		const timeout = setTimeout(resolve, ms);
		const onAbort = () => {
			clearTimeout(timeout);
			reject(signal?.reason instanceof Error ? signal.reason : new Error('aborted'));
		};
		if (signal?.aborted) {
			onAbort();
			return;
		}
		signal?.addEventListener('abort', onAbort, { once: true });
	});
}

async function fetchRdapResponse(rdapUrl: string, callerSignal?: AbortSignal, deadlineMs?: number): Promise<Response> {
	let lastResponse: Response | null = null;
	for (let attempt = 1; attempt <= RDAP_RETRY_MAX_ATTEMPTS; attempt++) {
		const remainingBudgetMs = typeof deadlineMs === 'number' ? deadlineMs - Date.now() : undefined;
		const resp = await fetch(rdapUrl, {
			redirect: 'manual',
			signal: composeFetchSignal(callerSignal, remainingBudgetMs),
			headers: { Accept: 'application/rdap+json, application/json' },
		});
		if (resp.ok || !RDAP_RETRYABLE_HTTP_STATUSES.has(resp.status) || attempt === RDAP_RETRY_MAX_ATTEMPTS) {
			return resp;
		}
		lastResponse = resp;
		// Clamp the `Retry-After` sleep against the remaining sync budget so a
		// server-controlled header can't blow past the tool-call cap. If the
		// budget is already exhausted, skip the sleep AND the next attempt —
		// the composed signal would just abort the retry fetch anyway.
		const postFetchRemaining = typeof deadlineMs === 'number' ? deadlineMs - Date.now() : undefined;
		const sleepMs = parseRetryAfterMs(resp.headers.get('Retry-After'), postFetchRemaining);
		if (typeof postFetchRemaining === 'number' && postFetchRemaining <= 0) {
			return resp;
		}
		await sleep(sleepMs, callerSignal);
	}
	return (
		lastResponse ??
		fetch(rdapUrl, {
			redirect: 'manual',
			signal: composeFetchSignal(callerSignal, typeof deadlineMs === 'number' ? deadlineMs - Date.now() : undefined),
			headers: { Accept: 'application/rdap+json, application/json' },
		})
	);
}

/** Find an event by action name. */
function findEvent(events: RdapEvent[] | undefined, action: string): RdapEvent | null {
	if (!Array.isArray(events)) return null;
	return events.find((e) => e.eventAction === action) ?? null;
}

/** Minimal Fetcher shape — matches Cloudflare service binding. */
interface FetcherLike {
	fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

import { z } from 'zod';

const WhoisFallbackPayloadSchema = z.object({
	registrar: z.string().max(256).nullable(),
	registrarIanaId: z.string().max(64).nullable().optional(),
	source: z.enum(['whois', 'redacted', 'notfound', 'error']),
});
type WhoisFallbackPayload = z.infer<typeof WhoisFallbackPayloadSchema>;

const WHOIS_REGISTRAR_LABELS = ['Registrar', 'Registrar Name', 'Sponsoring Registrar', 'Registrar Organization'] as const;

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseStructuredWhoisPayload(body: string): WhoisFallbackPayload | null {
	const trimmed = body.trim();
	if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
	try {
		const parsed = WhoisFallbackPayloadSchema.safeParse(JSON.parse(trimmed));
		return parsed.success ? parsed.data : { registrar: null, source: 'error' };
	} catch {
		return { registrar: null, source: 'error' };
	}
}

function extractWhoisRegistrarLabel(body: string): string | null {
	for (const line of body.split(/\r?\n/)) {
		for (const label of WHOIS_REGISTRAR_LABELS) {
			const match = line.match(new RegExp(`^\\s*${escapeRegExp(label)}\\s*:\\s*(.+?)\\s*$`, 'i'));
			const registrar = match?.[1]?.trim();
			if (registrar && registrar.length <= 256) return registrar;
		}
	}
	return null;
}

/**
 * Call the bv-whois shim Worker via service binding. Returns the structured
 * result, or { registrar: null, source: 'error' } on any failure (fail-soft).
 */
async function fetchWhoisRegistrar(
	domain: string,
	binding: FetcherLike | undefined,
	signal?: AbortSignal,
	deadlineMs?: number,
): Promise<WhoisFallbackPayload | null> {
	if (!binding) return null;
	// If the orchestrator deadline is already past, don't bother with a follow-on
	// WHOIS call — composeFetchSignal would yield an already-aborted signal and
	// we'd just return `error`. Surface that as a soft-null so the caller picks
	// up the prior RDAP outcome verbatim.
	if (typeof deadlineMs === 'number' && deadlineMs - Date.now() <= 0) {
		return { registrar: null, source: 'error' };
	}
	const remainingBudgetMs = typeof deadlineMs === 'number' ? deadlineMs - Date.now() : undefined;
	try {
		const resp = await binding.fetch('https://bv-whois/lookup', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ domain }),
			signal: composeFetchSignal(signal, remainingBudgetMs),
		});
		if (!resp.ok) return { registrar: null, source: 'error' };
		const body = await resp.text();
		const structured = parseStructuredWhoisPayload(body);
		if (structured) return structured;
		const registrar = extractWhoisRegistrarLabel(body);
		if (registrar) return { registrar, source: 'whois' };
		return { registrar: null, source: 'error' };
	} catch {
		return { registrar: null, source: 'error' };
	}
}

export type RegistrarSourceTag = 'rdap' | 'whois' | 'redacted' | 'notfound' | 'lookup_failed' | 'unknown';

interface RegistrarOutcome {
	source: RegistrarSourceTag;
	/** Stable token identifying *why* a lookup failed transiently. Set iff source === 'lookup_failed'. */
	failureReason?: string;
}

/**
 * Reconcile the RDAP code-path tag (`rdap` / 'lookup_failed' / 'unknown') with the
 * WHOIS shim's reported source. WHOIS deterministic answers (whois / redacted /
 * notfound) always win over an RDAP transient failure — we got an authoritative
 * answer, just from a different source. WHOIS `error` combined with an RDAP
 * failure carries through as `lookup_failed` (still retryable).
 */
function reconcileWithWhois(rdap: RegistrarOutcome, w: WhoisFallbackPayload | null): RegistrarOutcome {
	if (w?.source === 'whois' && w.registrar) return { source: 'whois' };
	if (w?.source === 'redacted') return { source: 'redacted' };
	if (w?.source === 'notfound') return { source: 'notfound' };
	if (w?.source === 'error') {
		return rdap.source === 'lookup_failed' ? rdap : { source: 'lookup_failed', failureReason: 'whois_error' };
	}
	// w === null (binding absent): RDAP outcome stands.
	return rdap;
}

/**
 * Emit a Registration details finding carrying the WHOIS-sourced registrar
 * (or marking the source as lookup_failed / unknown / redacted / notfound).
 * Used by the RDAP-failure code paths to surface fallback data with provenance.
 */
function buildWhoisFallbackFinding(domain: string, w: WhoisFallbackPayload | null, rdapOutcome: RegistrarOutcome) {
	const outcome = reconcileWithWhois(rdapOutcome, w);
	const registrar = w?.registrar ?? null;
	const registrarIanaId = w?.registrarIanaId ?? null;
	const detailParts: string[] = [];
	if (registrar) detailParts.push(`Registrar: ${registrar}`);
	detailParts.push(`Source: ${outcome.source}`);
	if (outcome.failureReason) detailParts.push(`Reason: ${outcome.failureReason}`);
	return createFinding(CATEGORY, 'Registration details', 'info', detailParts.join('. ') + '.', {
		domain,
		registrar,
		registrarIanaId,
		registrarSource: outcome.source,
		...(outcome.failureReason ? { registrarFailureReason: outcome.failureReason } : {}),
	});
}

export interface RdapCheckOptions {
	/** Service binding to bv-whois shim Worker — enables WHOIS fallback for non-RDAP TLDs. */
	whoisBinding?: FetcherLike;
	/**
	 * Caller AbortSignal — when fired, in-flight RDAP and WHOIS fetches cancel
	 * via composed AbortSignal.any() and a pre-check at the top of the function
	 * short-circuits to a lookup_failed finding. Threaded from the brand-audit
	 * pipeline so deadline aborts actually unwind RDAP work.
	 */
	signal?: AbortSignal;
	/**
	 * Wall-clock deadline (epoch ms) for the synchronous tool path. Used to
	 * clamp `Retry-After` sleeps, per-request fetch timeouts, and the WHOIS
	 * follow-on call against the remaining sync budget. When the handler
	 * threads `AbortSignal.timeout(RDAP_LOOKUP_SYNC_BUDGET_MS)` as the signal,
	 * it should pass `Date.now() + RDAP_LOOKUP_SYNC_BUDGET_MS` here so the
	 * orchestrator can introspect "how much budget is left" — `AbortSignal`
	 * alone can't answer that.
	 */
	deadlineMs?: number;
}

/**
 * Build a fetch signal that aborts on EITHER the per-request timeout OR caller
 * abort. When a `remainingBudgetMs` is supplied, the per-request timeout is
 * clamped to it so a single fetch can't outlive the orchestrator's tool-call
 * budget. A non-positive remaining budget produces an already-aborted signal
 * (the fetch returns immediately, the caller handles it as `caller_aborted`).
 */
function composeFetchSignal(callerSignal: AbortSignal | undefined, remainingBudgetMs?: number): AbortSignal {
	const perRequestMs =
		typeof remainingBudgetMs === 'number' ? Math.max(0, Math.min(RDAP_TIMEOUT_MS, remainingBudgetMs)) : RDAP_TIMEOUT_MS;
	const timeoutSignal = AbortSignal.timeout(perRequestMs);
	if (!callerSignal) return timeoutSignal;
	return AbortSignal.any([timeoutSignal, callerSignal]);
}

/**
 * Look up domain registration data via RDAP, falling back to WHOIS (via the
 * BV_WHOIS service binding) when RDAP can't answer.
 *
 * @param domain - The domain to look up
 * @param options - Optional fallback bindings
 * @returns CheckResult with registration findings
 */
export async function checkRdapLookup(domain: string, options: RdapCheckOptions = {}): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];
	const callerSignal = options.signal;
	const deadlineMs = options.deadlineMs;

	// Pre-check: caller signal already aborted → short-circuit to lookup_failed
	// without doing any I/O. Cuts wasted budget when the audit deadline fires
	// between scheduling and execution of this lookup.
	if (callerSignal?.aborted) {
		findings.push(
			createFinding(CATEGORY, 'Registration details', 'info', 'Source: lookup_failed. Reason: caller_aborted.', {
				domain,
				registrar: null,
				registrarIanaId: null,
				registrarSource: 'lookup_failed',
				registrarFailureReason: 'caller_aborted',
			}),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Extract TLD
	const labels = domain.split('.');
	const tld = labels[labels.length - 1];

	// Resolve RDAP server
	const rdapServerUrl = await resolveRdapServer(tld);
	if (!rdapServerUrl) {
		findings.push(
			createFinding(
				CATEGORY,
				'No RDAP server found',
				'info',
				`No RDAP server found for TLD ".${tld}". RDAP data unavailable for this domain.`,
				{
					domain,
					tld,
				},
			),
		);
		// Deterministic: TLD has no RDAP server. Not transient — keep as 'unknown'
		// (or whichever WHOIS provides). reconcileWithWhois handles the rest.
		const whois = await fetchWhoisRegistrar(domain, options.whoisBinding, callerSignal, deadlineMs);
		findings.push(buildWhoisFallbackFinding(domain, whois, { source: 'unknown' }));
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Fetch RDAP domain data
	let rdapData: RdapDomainResponse;
	try {
		const baseUrl = rdapServerUrl.endsWith('/') ? rdapServerUrl : `${rdapServerUrl}/`;
		const rdapUrl = `${baseUrl}domain/${domain}`;
		const resp = await fetchRdapResponse(rdapUrl, callerSignal, deadlineMs);

		if (!resp.ok) {
			findings.push(
				createFinding(
					CATEGORY,
					'RDAP lookup failed',
					'info',
					`RDAP server returned HTTP ${resp.status} for ${domain}. Registration data unavailable.`,
					{
						domain,
						httpStatus: resp.status,
					},
				),
			);
			const whois = await fetchWhoisRegistrar(domain, options.whoisBinding, callerSignal, deadlineMs);
			findings.push(buildWhoisFallbackFinding(domain, whois, { source: 'lookup_failed', failureReason: `rdap_http_${resp.status}` }));
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		rdapData = (await resp.json()) as RdapDomainResponse;
	} catch (err) {
		const message = err instanceof Error ? err.message : 'Unknown error';
		// Caller-abort during fetch surfaces as a distinct reason so the retry
		// policy can distinguish budget exhaustion from upstream RDAP flake.
		const reason = callerSignal?.aborted ? 'caller_aborted' : 'rdap_fetch_error';
		findings.push(
			createFinding(CATEGORY, 'RDAP lookup failed', 'info', `RDAP lookup failed for ${domain}: ${message}`, {
				domain,
				error: message,
			}),
		);
		const whois = await fetchWhoisRegistrar(domain, options.whoisBinding, callerSignal, deadlineMs);
		findings.push(buildWhoisFallbackFinding(domain, whois, { source: 'lookup_failed', failureReason: reason }));
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Parse registrar
	const registrarEntity = findEntityByRole(rdapData.entities, 'registrar');
	let registrarName = registrarEntity ? extractVcardName(registrarEntity) : null;
	let registrarIanaId = extractRegistrarIanaId(registrarEntity);
	if (!registrarName) {
		const publicIdEntity = findEntityByRegistrarIanaId(rdapData.entities);
		registrarName = publicIdEntity ? extractVcardName(publicIdEntity) : null;
		registrarIanaId = extractRegistrarIanaId(publicIdEntity);
	}
	let registrarSource: RegistrarSourceTag = registrarName ? 'rdap' : 'unknown';
	let registrarFailureReason: string | undefined;
	if (!registrarName) {
		const whois = await fetchWhoisRegistrar(domain, options.whoisBinding, callerSignal, deadlineMs);
		// Phase 7: this path is the success-side RDAP-rescue branch; keep the
		// unknown→whois reconcile (not lookup_failed) as established in Phase 1.
		// RDAP didn't return a registrar entity — that's a structural miss, not a transient
		// failure. So pass 'unknown' as the RDAP-side outcome (NOT lookup_failed); WHOIS
		// can still elevate to deterministic answer or 'whois_error'.
		const reconciled = reconcileWithWhois({ source: 'unknown' }, whois);
		const outcome: RegistrarOutcome = reconciled.source === 'lookup_failed' ? { source: 'redacted' } : reconciled;
		registrarSource = outcome.source;
		registrarFailureReason = outcome.failureReason;
		if (whois?.registrar) registrarName = whois.registrar;
		if (whois?.registrarIanaId) registrarIanaId = whois.registrarIanaId;
	}

	// Parse registrant
	const registrantEntity = findEntityByRole(rdapData.entities, 'registrant');
	const registrantName = registrantEntity ? extractVcardName(registrantEntity) : null;
	const registrantCountry = registrantEntity ? extractVcardCountry(registrantEntity) : null;

	// Parse events
	const registrationEvent = findEvent(rdapData.events, 'registration');
	const expirationEvent = findEvent(rdapData.events, 'expiration');
	const lastChangedEvent = findEvent(rdapData.events, 'last changed');

	// Calculate domain age
	let domainAgeDays: number | null = null;
	if (registrationEvent?.eventDate) {
		const creationTime = new Date(registrationEvent.eventDate).getTime();
		if (Number.isFinite(creationTime)) {
			domainAgeDays = Math.floor((Date.now() - creationTime) / (1000 * 60 * 60 * 24));
		}
	}

	// Calculate days until expiration
	let daysUntilExpiration: number | null = null;
	if (expirationEvent?.eventDate) {
		const expirationTime = new Date(expirationEvent.eventDate).getTime();
		if (Number.isFinite(expirationTime)) {
			daysUntilExpiration = Math.floor((expirationTime - Date.now()) / (1000 * 60 * 60 * 24));
		}
	}

	// EPP status
	const eppStatus = Array.isArray(rdapData.status) ? rdapData.status : [];

	// Build metadata
	const metadata: Record<string, unknown> = {
		domain,
		registrar: registrarName,
		registrarIanaId,
		registrarSource,
		...(registrarFailureReason ? { registrarFailureReason } : {}),
		registrant: registrantName,
		registrantCountry,
		creationDate: registrationEvent?.eventDate ?? null,
		expirationDate: expirationEvent?.eventDate ?? null,
		lastChanged: lastChangedEvent?.eventDate ?? null,
		eppStatus,
		rdapServer: rdapServerUrl,
	};

	if (domainAgeDays !== null) {
		metadata.domainAgeDays = domainAgeDays;
	}
	if (daysUntilExpiration !== null) {
		metadata.daysUntilExpiration = daysUntilExpiration;
	}

	// Findings

	// Medium: newly registered (< 30 days)
	if (domainAgeDays !== null && domainAgeDays < 30) {
		findings.push(
			createFinding(
				CATEGORY,
				'Newly registered domain',
				'medium',
				`${domain} was registered ${domainAgeDays} day${domainAgeDays !== 1 ? 's' : ''} ago (${registrationEvent!.eventDate}). Newly registered domains are commonly used for phishing and spam.`,
				metadata,
			),
		);
	}

	// Low: expiring within 30 days
	if (daysUntilExpiration !== null && daysUntilExpiration <= 30 && daysUntilExpiration >= 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'Domain expiring soon',
				'low',
				`${domain} expires in ${daysUntilExpiration} day${daysUntilExpiration !== 1 ? 's' : ''} (${expirationEvent!.eventDate}). Expired domains can be re-registered by attackers.`,
				metadata,
			),
		);
	}

	// Info: standard registration details (always present)
	const parts: string[] = [];
	if (registrarName) parts.push(`Registrar: ${registrarName}`);
	if (registrantName) parts.push(`Registrant: ${registrantName}`);
	if (registrantCountry) parts.push(`Country: ${registrantCountry}`);
	if (registrationEvent?.eventDate) parts.push(`Created: ${registrationEvent.eventDate.split('T')[0]}`);
	if (expirationEvent?.eventDate) parts.push(`Expires: ${expirationEvent.eventDate.split('T')[0]}`);
	if (lastChangedEvent?.eventDate) parts.push(`Updated: ${lastChangedEvent.eventDate.split('T')[0]}`);
	if (eppStatus.length > 0) parts.push(`Status: ${eppStatus.join(', ')}`);
	if (domainAgeDays !== null) parts.push(`Age: ${domainAgeDays} days`);

	findings.push(
		createFinding(
			CATEGORY,
			'Registration details',
			'info',
			parts.length > 0 ? parts.join('. ') + '.' : `RDAP data retrieved for ${domain} but no structured fields found.`,
			metadata,
		),
	);

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
