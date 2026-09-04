// SPDX-License-Identifier: BUSL-1.1

/**
 * Enrichment probes for the lookalike check (Defect L / issue #264 + #263).
 *
 * One RDAP fetch and at most one HEAD probe per candidate, both on tight
 * budgets, yielding the corroborating signals the severity calibrator and the
 * attribution predicates consume:
 *
 *  - `registrationDays` — the "recently registered" corroborator (#264);
 *  - `registrantOrg` — the same-entity correlation input (#263);
 *  - `registrarIanaId` / `registrarName` — the brand-held-registration input;
 *  - `hasWebContent` — the "parked / unreachable" corroborator.
 *
 * EVERY path here is FAIL-SOFT and the direction of each failure default is
 * load-bearing: a missing RDAP field becomes `null` ("unknown", never elevates
 * severity and never suppresses a threat), and an UNATTEMPTED HEAD probe
 * becomes `true` ("has content", so a probe that never ran cannot synthesise a
 * HIGH). Nothing in this module throws out of the tool.
 *
 * ⚠️ FAN-OUT IS BOUNDED, AND THE BOUND IS THE PLATFORM'S (#867). A Worker
 * invocation may hold at most SIX connections simultaneously waiting for
 * response headers (developers.cloudflare.com/workers/platform/limits/
 * #simultaneous-open-connections); further `fetch()` calls QUEUE. This module
 * used to dispatch every candidate's RDAP + HEAD at once — ~48 fetches for a
 * 25-candidate seed — each armed with `AbortSignal.timeout(2500)` at call time,
 * so the timers of the ~42 queued fetches ran while they waited for a slot and
 * they aborted before the request was ever sent. The fail-soft then recorded
 * `registrationDays: null` for every candidate past the first slot-fill (and
 * `hasWebContent: false`, a manufactured HIGH corroborator). Measured live on
 * anthropic.com 2026-09-04: exactly the first 8 candidates carried an age, the
 * first 6 `hasWebContent: true`, every later one `null` + `false`. `.ai` seeds
 * (#780) only looked fixed because a short brand yields few candidates.
 *
 * Two pools now share the six slots — {@link RDAP_PROBE_CONCURRENCY} +
 * {@link WEB_PROBE_CONCURRENCY} — and each fetch arms its timeout when it is
 * actually dispatched. Do not widen the pools past six in total, and do not
 * re-introduce a `candidates.map(fetch)` fan-out anywhere in this module.
 */

import { safeFetch } from '../lib/safe-fetch';
import { readJsonResponseCapped } from '../lib/response-body';
import { mapConcurrent } from '../lib/map-concurrent';
import { extractRegistrantOrg, findEntityByRole } from './check-rdap-lookup';
import { FALLBACK_RDAP_SERVERS } from './rdap-fallback-servers';
import { isDisposableMxHost } from './lookalike-severity';
import type { LookalikeResult } from './lookalike-dns';

/** Per-probe budgets for the Defect L enrichment probes. Each timer is armed when the fetch is DISPATCHED, never earlier (#867). */
const RDAP_PROBE_TIMEOUT_MS = 2500;
const WEB_PROBE_TIMEOUT_MS = 2500;
const RDAP_PROBE_MAX_BODY_BYTES = 512 * 1024;

/**
 * Pool widths. Their SUM is the Workers simultaneous-open-connection cap (6):
 * nothing else in `check_lookalikes` is fetching while enrichment runs (the
 * DNS phases complete before it), so the two pools own the whole budget. RDAP
 * gets the larger share because the age lookup is the signal #867 is about;
 * the HEAD probe is a corroborator whose unattempted default is safe.
 */
export const RDAP_PROBE_CONCURRENCY = 4;
export const WEB_PROBE_CONCURRENCY = 2;

/**
 * Why a candidate's registration age is what it is. `ok` is the only value
 * under which `registrationDays` is a number; every other value means the age
 * is UNKNOWN for that stated reason — never "absent", never "old". Exposed on
 * every enriched finding so a consumer can tell "we could not measure" from
 * "we measured nothing notable" (#867, #780).
 */
export type RegistrationLookupOutcome =
	/** RDAP answered with a parseable `registration` event. */
	| 'ok'
	/** RDAP answered 200 but published no parseable `registration` event. */
	| 'no_registration_event'
	/** No RDAP server is known for the candidate's TLD (`FALLBACK_RDAP_SERVERS`). */
	| 'unsupported_tld'
	/** The registry answered 404 for the name. */
	| 'not_found'
	/** The registry answered 429 — rate-limited. */
	| 'throttled'
	/** No answer within the per-probe budget (or the remaining enrichment deadline). */
	| 'timeout'
	/** Transport error, non-2xx other than the above, or an unreadable body. */
	| 'failed'
	/** The enrichment deadline was already spent before this candidate's turn; no request was issued. */
	| 'not_attempted';

export interface LookalikeCorroborators {
	registrationDays: number | null;
	/** `true` iff `registrationDays` is `null`; see {@link registrationLookup} for why. */
	ageUnknown: boolean;
	/** Why the age is known or not — `ok` iff `registrationDays` is a number. */
	registrationLookup: RegistrationLookupOutcome;
	mxOnDisposable: boolean;
	hasWebContent: boolean;
	/**
	 * Normalised RDAP registrant org for this candidate, harvested from the same
	 * single RDAP fetch as {@link registrationDays}. `null` when RDAP failed,
	 * returned no registrant entity, or the org field was empty — in which case
	 * the same-entity correlation fails soft (the calibrated threat severity
	 * stands; a real threat is never suppressed on missing RDAP).
	 */
	registrantOrg: string | null;
	/**
	 * Registry-published IANA registrar ID for this candidate, harvested from
	 * the same single RDAP fetch as everything else here. Feeds
	 * `isBrandHeldRegistration`; `null` fails soft to "no evidence".
	 */
	registrarIanaId: string | null;
	/** Registrar display name, for report prose only. */
	registrarName: string | null;
}

export interface EnrichmentOptions {
	/**
	 * Wall-clock deadline (epoch ms) for the whole enrichment phase. A probe
	 * whose turn comes after it is NOT issued (`not_attempted`); a probe that
	 * starts before it has its per-probe timeout clamped to the remainder.
	 * Absent → each probe gets its full per-probe budget (direct callers).
	 */
	deadlineMs?: number;
}

/**
 * Order candidates so the ones the age signal protects are looked up FIRST:
 * mail-capable candidates (the age corroborator can lift them to HIGH, and a
 * pre-dating age lets a consumer exclude them) ahead of web-only ones. Stable
 * within each group, so a tight deadline drops the tail of the web-only set,
 * never a mail host.
 */
export function prioritiseForEnrichment(candidates: readonly LookalikeResult[]): LookalikeResult[] {
	const mail: LookalikeResult[] = [];
	const rest: LookalikeResult[] = [];
	for (const c of candidates) (c.hasMX ? mail : rest).push(c);
	return [...mail, ...rest];
}

/**
 * Run the Defect L enrichment probes (RDAP registration age + web HEAD probe)
 * for every candidate through two bounded pools (see the module JSDoc for why
 * the bound is six). Failure to enrich is fail-soft: missing RDAP data becomes
 * `registrationDays: null` WITH a stated {@link RegistrationLookupOutcome}
 * (treated as "unknown — not recent"), and an unattempted HEAD probe becomes
 * `hasWebContent: true` to avoid synthesising HIGH out of nothing.
 * `mxOnDisposable` is derived synchronously from the already-parsed MX
 * exchanges, no extra DNS needed.
 */
export async function enrichLookalikes(
	candidates: LookalikeResult[],
	options: EnrichmentOptions = {},
): Promise<Map<string, LookalikeCorroborators>> {
	const map = new Map<string, LookalikeCorroborators>();
	if (candidates.length === 0) return map;
	const ordered = prioritiseForEnrichment(candidates);
	const deadlineMs = options.deadlineMs;
	// Two independent pools: a slow HEAD probe (dark domains hang for the full
	// budget) must not hold an RDAP slot hostage. Neither probe ever throws, so
	// mapConcurrent cannot reject.
	const [rdapResults, webResults] = await Promise.all([
		mapConcurrent(ordered, RDAP_PROBE_CONCURRENCY, (candidate) => probeRdap(candidate.domain, deadlineMs)),
		mapConcurrent(ordered, WEB_PROBE_CONCURRENCY, (candidate) =>
			candidate.hasA ? probeHasWebContent(candidate.domain, deadlineMs) : Promise.resolve(true),
		),
	]);
	ordered.forEach((candidate, i) => {
		const rdap = rdapResults[i];
		map.set(candidate.domain, {
			registrationDays: rdap.registrationDays,
			ageUnknown: rdap.registrationDays === null,
			registrationLookup: rdap.lookup,
			mxOnDisposable: candidate.mxExchanges.some(isDisposableMxHost),
			hasWebContent: webResults[i],
			registrantOrg: rdap.registrantOrg,
			registrarIanaId: rdap.registrarIanaId,
			registrarName: rdap.registrarName,
		});
	});
	return map;
}

/** Result of the single lightweight RDAP probe per candidate. */
export interface RdapProbeResult {
	/** Age in days since the RDAP `registration` event, or `null` on any failure / missing data. */
	registrationDays: number | null;
	/** Why {@link registrationDays} is or is not populated. */
	lookup: RegistrationLookupOutcome;
	/** Normalised RDAP registrant org, or `null` on any failure / missing data. */
	registrantOrg: string | null;
	/**
	 * Registry-published IANA registrar ID, or `null` on any failure / absence.
	 * Distinct in kind from {@link registrantOrg}: assigned by ICANN, published
	 * by the registry, and not settable by the registrant — see
	 * `BRAND_PROTECTION_REGISTRAR_IANA_IDS` in `lookalike-attribution.ts`.
	 */
	registrarIanaId: string | null;
	/** Registrar display name, for report prose only. Never compared. */
	registrarName: string | null;
}

/** Empty probe result — the "never looked" shape, used when a lookup is skipped outright (fail-soft). */
export const EMPTY_RDAP_PROBE: RdapProbeResult = {
	registrationDays: null,
	lookup: 'not_attempted',
	registrantOrg: null,
	registrarIanaId: null,
	registrarName: null,
};

/** An attempted-but-unanswered probe: same nulls as {@link EMPTY_RDAP_PROBE}, with the reason recorded. */
function failedProbe(lookup: Exclude<RegistrationLookupOutcome, 'ok'>): RdapProbeResult {
	return { ...EMPTY_RDAP_PROBE, lookup };
}

/**
 * Remaining per-probe budget: the probe's own ceiling, clamped to whatever is
 * left before `deadlineMs`. `<= 0` means "do not issue the request".
 */
function remainingBudgetMs(probeTimeoutMs: number, deadlineMs: number | undefined): number {
	if (typeof deadlineMs !== 'number') return probeTimeoutMs;
	return Math.min(probeTimeoutMs, deadlineMs - Date.now());
}

/**
 * Pull the registrar's IANA ID and display name out of a parsed RDAP domain
 * response. Local to the lookalike surface rather than imported because
 * `check-rdap-lookup.ts` keeps its vCard/publicId readers private; only
 * `findEntityByRole` is exported, so the traversal is reused and just the two
 * field reads are done here.
 *
 * Fail-soft in every branch — a non-conforming shape yields nulls, which the
 * brand-held predicate treats as "no evidence" (never as a match).
 */
function extractRegistrar(rdapData: unknown): { ianaId: string | null; name: string | null } {
	if (typeof rdapData !== 'object' || rdapData === null) return { ianaId: null, name: null };
	const entities = (rdapData as { entities?: unknown }).entities;
	if (!Array.isArray(entities)) return { ianaId: null, name: null };
	const registrar = findEntityByRole(entities as Parameters<typeof findEntityByRole>[0], 'registrar');
	if (!registrar) return { ianaId: null, name: null };

	let ianaId: string | null = null;
	const publicIds = (registrar as { publicIds?: unknown }).publicIds;
	if (Array.isArray(publicIds)) {
		for (const publicId of publicIds) {
			if (typeof publicId !== 'object' || publicId === null) continue;
			const { type, identifier } = publicId as { type?: unknown; identifier?: unknown };
			if (typeof type === 'string' && /^IANA Registrar ID$/i.test(type.trim()) && typeof identifier === 'string' && identifier.trim()) {
				ianaId = identifier.trim();
				break;
			}
		}
	}

	let name: string | null = null;
	const vcardArray = (registrar as { vcardArray?: unknown }).vcardArray;
	if (Array.isArray(vcardArray) && vcardArray[0] === 'vcard' && Array.isArray(vcardArray[1])) {
		for (const prop of vcardArray[1] as unknown[]) {
			if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string' && prop[3].trim()) {
				name = prop[3].trim();
				break;
			}
		}
	}
	return { ianaId, name };
}

/**
 * Lightweight RDAP lookup constrained for use inside the lookalike check.
 * Hits the hardcoded {@link FALLBACK_RDAP_SERVERS} map only (no IANA bootstrap),
 * single fetch, hard 2.5s timeout armed at dispatch, no retries. From that
 * single response it derives BOTH the registration age (issue #264
 * corroborator) AND the registrant org (issue #263 same-entity correlation) —
 * no extra fetch for the org signal. Any failure / missing data yields `null`
 * for the affected field PLUS a `lookup` reason; the calibrator treats a null
 * age as "unknown" (never elevates severity) and the same-entity check treats
 * a null org as "no match" (never suppresses a real threat).
 *
 * ⚠️ A DEAD ENTRY IN THAT MAP STILL DEGRADES QUIETLY (#780) — it surfaces as
 * `lookup: 'failed'` / `'timeout'` on every domain under the TLD rather than
 * as an error. The class-level guard is `scripts/audits/rdap-fallback-reconcile.ts`,
 * which reconciles the table against IANA's authoritative bootstrap out-of-band.
 */
async function probeRdap(domain: string, deadlineMs?: number): Promise<RdapProbeResult> {
	const labels = domain.split('.');
	const tld = labels[labels.length - 1]?.toLowerCase();
	if (!tld) return failedProbe('unsupported_tld');
	const serverUrl = FALLBACK_RDAP_SERVERS[tld];
	if (!serverUrl) return failedProbe('unsupported_tld');
	const budgetMs = remainingBudgetMs(RDAP_PROBE_TIMEOUT_MS, deadlineMs);
	if (budgetMs <= 0) return failedProbe('not_attempted');
	// Armed HERE, at dispatch — the pool guarantees a connection slot is free,
	// so the timer measures the server, not a queue (#867).
	const signal = AbortSignal.timeout(budgetMs);
	try {
		const baseUrl = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`;
		const rdapUrl = `${baseUrl}domain/${domain}`;
		// The RDAP host comes from the FALLBACK_RDAP_SERVERS map — not statically
		// trusted as a class (the sibling fetchRdapResponse path derives the same
		// host from the network-sourced IANA bootstrap), so route through safeFetch
		// for parity: validateOutboundUrl() re-validates the destination host (SSRF
		// gate) and manual redirect stops the worker chasing a server-supplied
		// Location. safeFetch throws on a blocked host (matching native fetch error
		// semantics); the surrounding try/catch degrades it to a failed probe
		// exactly like any other probe failure (fail-soft, never throws out of the tool).
		const resp = await safeFetch(rdapUrl, {
			redirect: 'manual',
			signal,
			headers: { Accept: 'application/rdap+json, application/json' },
		});
		if (!resp.ok) {
			void resp.body?.cancel().catch(() => undefined);
			if (resp.status === 429) return failedProbe('throttled');
			if (resp.status === 404) return failedProbe('not_found');
			return failedProbe('failed');
		}
		const data = await readJsonResponseCapped<{ events?: Array<{ eventAction?: string; eventDate?: string }> }>(
			resp,
			RDAP_PROBE_MAX_BODY_BYTES,
		);
		if (data === null) return failedProbe('failed');
		const registration = Array.isArray(data.events) ? data.events.find((e) => e.eventAction === 'registration') : undefined;
		let registrationDays: number | null = null;
		if (registration?.eventDate) {
			const creationTime = new Date(registration.eventDate).getTime();
			if (Number.isFinite(creationTime)) {
				registrationDays = Math.floor((Date.now() - creationTime) / (1000 * 60 * 60 * 24));
			}
		}
		const registrar = extractRegistrar(data);
		return {
			registrationDays,
			lookup: registrationDays === null ? 'no_registration_event' : 'ok',
			registrantOrg: extractRegistrantOrg(data),
			registrarIanaId: registrar.ianaId,
			registrarName: registrar.name,
		};
	} catch {
		return failedProbe(signal.aborted ? 'timeout' : 'failed');
	}
}

/**
 * Fetch the scan domain's own registration record — registrant org for the
 * same-entity correlation (issue #263) AND the registry-published registrar ID
 * for `isBrandHeldRegistration`. ONE fetch serves both; reuses
 * {@link probeRdap} and fails soft to {@link EMPTY_RDAP_PROBE}'s nulls.
 */
export async function probePrimaryRegistration(domain: string, options: EnrichmentOptions = {}): Promise<RdapProbeResult> {
	return probeRdap(domain, options.deadlineMs);
}

/**
 * HEAD probe the candidate domain to confirm web content is reachable.
 * Fail-soft: any error (connection refused, timeout, DNS miss, TLS error)
 * returns `true` so a flaky probe can't synthesise a HIGH severity via the
 * "no-web-content" corroborator. Parked-or-refused domains return `false`.
 *
 * 5xx responses also count as "has content" — we got reached the server,
 * the server just errored. Phishing infra rarely 5xx's; parked-page infra
 * usually 200's with adverts. The only consistent "no content" signal is a
 * hard transport failure.
 *
 * A probe whose turn comes after `deadlineMs` is NOT issued and reports `true`
 * — "unknown" must fail toward the safe side, never toward the HIGH corroborator.
 * The same law for a probe that TIMES OUT (#894 residual 2): a host that has
 * not answered within the budget is unknown, not "no content" — a slow parked
 * host and a slow real one look identical from here. Only a MEASURED refusal
 * (reset, refused, TLS failure, no route) is the no-content signal.
 */
export async function probeHasWebContent(domain: string, deadlineMs?: number): Promise<boolean> {
	const budgetMs = remainingBudgetMs(WEB_PROBE_TIMEOUT_MS, deadlineMs);
	if (budgetMs <= 0) return true;
	// Armed HERE, at dispatch — the pool guarantees a connection slot is free (#867).
	const signal = AbortSignal.timeout(budgetMs);
	try {
		// safeFetch + manual redirect: the candidate is attacker-influenced, so we
		// MUST NOT auto-follow a 302 → internal/Cloudflare host (blind SSRF oracle,
		// OWASP A10). safeFetch validates the destination hostname; manual redirect
		// stops the worker from chasing an attacker-supplied Location. A 3xx still
		// proves the host is reachable, so any response counts as "has content".
		const resp = await safeFetch(`https://${domain}/`, {
			method: 'HEAD',
			redirect: 'manual',
			signal,
		});
		// Any HTTP response (incl. 3xx) means the host is reachable — content exists.
		return Boolean(resp);
	} catch {
		// Timed out → unknown → `true` (never the HIGH corroborator).
		// Measured transport refusal (reset, refused, DNS/TLS failure) → no content.
		return signal.aborted;
	}
}
