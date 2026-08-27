// SPDX-License-Identifier: BUSL-1.1

/**
 * Enrichment probes for the lookalike check (Defect L / issue #264 + #263).
 *
 * Extracted VERBATIM from `check-lookalikes.ts` (pure split, no behaviour
 * change). One RDAP fetch and at most one HEAD probe per candidate, both on
 * tight budgets, yielding the corroborating signals the severity calibrator and
 * the attribution predicates consume:
 *
 *  - `registrationDays` — the "recently registered" corroborator (#264);
 *  - `registrantOrg` — the same-entity correlation input (#263);
 *  - `registrarIanaId` / `registrarName` — the brand-held-registration input;
 *  - `hasWebContent` — the "parked / unreachable" corroborator.
 *
 * EVERY path here is FAIL-SOFT and the direction of each failure default is
 * load-bearing: a missing RDAP field becomes `null` ("unknown", never elevates
 * severity and never suppresses a threat), and a failed HEAD probe becomes
 * `true` ("has content", so a flaky probe cannot synthesise a HIGH). Nothing in
 * this module throws out of the tool.
 */

import { safeFetch } from '../lib/safe-fetch';
import { readJsonResponseCapped } from '../lib/response-body';
import { extractRegistrantOrg, findEntityByRole } from './check-rdap-lookup';
import { FALLBACK_RDAP_SERVERS } from './rdap-fallback-servers';
import { isDisposableMxHost } from './lookalike-severity';
import type { LookalikeResult } from './lookalike-dns';

/** Budgets for the Defect L enrichment probes. Both are intentionally tight so 12 candidates × (RDAP + HEAD) stays under LOOKALIKE_TIMEOUT_MS. */
const RDAP_PROBE_TIMEOUT_MS = 2500;
const WEB_PROBE_TIMEOUT_MS = 2500;
const RDAP_PROBE_MAX_BODY_BYTES = 512 * 1024;

export interface LookalikeCorroborators {
	registrationDays: number | null;
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

/**
 * Run the Defect L enrichment probes (RDAP registration age + web HEAD probe)
 * for every candidate in parallel. Failure to enrich is fail-soft: missing
 * RDAP data becomes `registrationDays: null` (treated as "unknown — not recent")
 * and a probe error becomes `hasWebContent: true` to avoid synthesising HIGH
 * out of nothing. `mxOnDisposable` is derived synchronously from the already-
 * parsed MX exchanges, no extra DNS needed.
 */
export async function enrichLookalikes(candidates: LookalikeResult[]): Promise<Map<string, LookalikeCorroborators>> {
	const map = new Map<string, LookalikeCorroborators>();
	if (candidates.length === 0) return map;
	await Promise.allSettled(
		candidates.map(async (candidate) => {
			const [rdap, hasWebContent] = await Promise.all([
				probeRdap(candidate.domain),
				candidate.hasA ? probeHasWebContent(candidate.domain) : Promise.resolve(true),
			]);
			const mxOnDisposable = candidate.mxExchanges.some(isDisposableMxHost);
			map.set(candidate.domain, {
				registrationDays: rdap.registrationDays,
				mxOnDisposable,
				hasWebContent,
				registrantOrg: rdap.registrantOrg,
				registrarIanaId: rdap.registrarIanaId,
				registrarName: rdap.registrarName,
			});
		}),
	);
	return map;
}

/** Result of the single lightweight RDAP probe per candidate. */
export interface RdapProbeResult {
	/** Age in days since the RDAP `registration` event, or `null` on any failure / missing data. */
	registrationDays: number | null;
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

/** Empty probe result — used for early-outs and the catch path (fail-soft). */
export const EMPTY_RDAP_PROBE: RdapProbeResult = { registrationDays: null, registrantOrg: null, registrarIanaId: null, registrarName: null };

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
 * single fetch, hard 2.5s timeout, no retries. From that single response it
 * derives BOTH the registration age (issue #264 corroborator) AND the registrant
 * org (issue #263 same-entity correlation) — no extra fetch for the org signal.
 * Any failure / missing data yields `null` for the affected field, which the
 * calibrator treats as "unknown" (never elevates severity) and the same-entity
 * check treats as "no match" (never suppresses a real threat).
 *
 * ⚠️ A DEAD ENTRY IN THAT MAP DEGRADES SILENTLY (#780) — a host that does not
 * resolve is indistinguishable here from "old domain, nothing notable". The
 * class-level guard is `scripts/audits/rdap-fallback-reconcile.ts`, which
 * reconciles the table against IANA's authoritative bootstrap out-of-band.
 */
async function probeRdap(domain: string): Promise<RdapProbeResult> {
	const labels = domain.split('.');
	const tld = labels[labels.length - 1]?.toLowerCase();
	if (!tld) return EMPTY_RDAP_PROBE;
	const serverUrl = FALLBACK_RDAP_SERVERS[tld];
	if (!serverUrl) return EMPTY_RDAP_PROBE;
	try {
		const baseUrl = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`;
		const rdapUrl = `${baseUrl}domain/${domain}`;
		// The RDAP host comes from the FALLBACK_RDAP_SERVERS map — not statically
		// trusted as a class (the sibling fetchRdapResponse path derives the same
		// host from the network-sourced IANA bootstrap), so route through safeFetch
		// for parity: validateOutboundUrl() re-validates the destination host (SSRF
		// gate) and manual redirect stops the worker chasing a server-supplied
		// Location. safeFetch throws on a blocked host (matching native fetch error
		// semantics); the surrounding try/catch degrades it to EMPTY_RDAP_PROBE
		// exactly like any other probe failure (fail-soft, never throws out of the tool).
		const resp = await safeFetch(rdapUrl, {
			redirect: 'manual',
			signal: AbortSignal.timeout(RDAP_PROBE_TIMEOUT_MS),
			headers: { Accept: 'application/rdap+json, application/json' },
		});
		if (!resp.ok) {
			void resp.body?.cancel();
			return EMPTY_RDAP_PROBE;
		}
		const data = await readJsonResponseCapped<{ events?: Array<{ eventAction?: string; eventDate?: string }> }>(
			resp,
			RDAP_PROBE_MAX_BODY_BYTES,
		);
		if (data === null) return EMPTY_RDAP_PROBE;
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
			registrantOrg: extractRegistrantOrg(data),
			registrarIanaId: registrar.ianaId,
			registrarName: registrar.name,
		};
	} catch {
		return EMPTY_RDAP_PROBE;
	}
}

/**
 * Fetch the scan domain's own registration record — registrant org for the
 * same-entity correlation (issue #263) AND the registry-published registrar ID
 * for `isBrandHeldRegistration`. ONE fetch serves both; reuses
 * {@link probeRdap} and fails soft to {@link EMPTY_RDAP_PROBE}.
 */
export async function probePrimaryRegistration(domain: string): Promise<RdapProbeResult> {
	return probeRdap(domain);
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
 */
export async function probeHasWebContent(domain: string): Promise<boolean> {
	try {
		// safeFetch + manual redirect: the candidate is attacker-influenced, so we
		// MUST NOT auto-follow a 302 → internal/Cloudflare host (blind SSRF oracle,
		// OWASP A10). safeFetch validates the destination hostname; manual redirect
		// stops the worker from chasing an attacker-supplied Location. A 3xx still
		// proves the host is reachable, so any response counts as "has content".
		const resp = await safeFetch(`https://${domain}/`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(WEB_PROBE_TIMEOUT_MS),
		});
		// Any HTTP response (incl. 3xx) means the host is reachable — content exists.
		return Boolean(resp);
	} catch {
		// Transport failure (refused, timeout, DNS) — treat as no content (HIGH corroborator).
		return false;
	}
}
