// SPDX-License-Identifier: BUSL-1.1

/**
 * RDAP Lookup tool — Domain Registration Data.
 * Fetches domain registration data via RDAP (modern WHOIS replacement).
 * Uses only HTTP fetch (no DNS queries).
 */

import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

const CATEGORY = 'rdap' as CheckCategory;

/** RDAP bootstrap URL (IANA). */
const IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/** Hardcoded RDAP server fallbacks for common TLDs. */
const FALLBACK_RDAP_SERVERS: Record<string, string> = {
	com: 'https://rdap.verisign.com/com/v1/',
	net: 'https://rdap.verisign.com/net/v1/',
	org: 'https://rdap.org/',
	info: 'https://rdap.afilias.net/rdap/info/',
	io: 'https://rdap.nic.io/',
};

/** Module-level bootstrap cache (per isolate lifetime). */
let bootstrapCache: Record<string, string> | null = null;

/** Reset bootstrap cache — exported for test isolation. */
export function _resetBootstrapCache(): void {
	bootstrapCache = null;
}

/** Timeout for all outbound RDAP fetches (ms). */
const RDAP_TIMEOUT_MS = 10_000;

interface RdapEvent {
	eventAction: string;
	eventDate: string;
}

interface RdapVcardProperty {
	0: string;  // property name
	1: Record<string, unknown>;  // parameters
	2: string;  // type
	3: unknown;  // value
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
 * Fetch and parse the IANA RDAP bootstrap file.
 * Caches result in module-level variable for isolate lifetime.
 * Returns a TLD → RDAP server URL map.
 */
async function fetchBootstrap(): Promise<Record<string, string>> {
	if (bootstrapCache) return bootstrapCache;

	try {
		const resp = await fetch(IANA_BOOTSTRAP_URL, {
			redirect: 'manual',
			signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
			headers: { Accept: 'application/json' },
		});
		if (!resp.ok) return {};

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

		bootstrapCache = map;
		return map;
	} catch {
		return {};
	}
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

/**
 * Call the bv-whois shim Worker via service binding. Returns the structured
 * result, or { registrar: null, source: 'error' } on any failure (fail-soft).
 */
async function fetchWhoisRegistrar(domain: string, binding: FetcherLike | undefined): Promise<WhoisFallbackPayload | null> {
	if (!binding) return null;
	try {
		const resp = await binding.fetch('https://bv-whois/lookup', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ domain }),
		});
		if (!resp.ok) return { registrar: null, source: 'error' };
		const raw = await resp.json();
		const parsed = WhoisFallbackPayloadSchema.safeParse(raw);
		if (!parsed.success) return { registrar: null, source: 'error' };
		return parsed.data;
	} catch {
		return { registrar: null, source: 'error' };
	}
}

/**
 * Map a WHOIS-fallback payload to the `registrarSource` value used in finding metadata.
 * Returns 'unknown' when the fallback was unavailable or failed.
 */
function whoisSourceToRegistrarSource(w: WhoisFallbackPayload | null): 'whois' | 'redacted' | 'notfound' | 'unknown' {
	if (!w) return 'unknown';
	if (w.source === 'whois' && w.registrar) return 'whois';
	if (w.source === 'redacted') return 'redacted';
	if (w.source === 'notfound') return 'notfound';
	return 'unknown';
}

/**
 * Emit a Registration details finding carrying the WHOIS-sourced registrar
 * (or marking the source as unknown / redacted / notfound). Used by the
 * RDAP-failure code paths to surface fallback data with provenance metadata.
 */
function buildWhoisFallbackFinding(domain: string, w: WhoisFallbackPayload | null) {
	const registrarSource = whoisSourceToRegistrarSource(w);
	const registrar = w?.registrar ?? null;
	const registrarIanaId = w?.registrarIanaId ?? null;
	const detailParts: string[] = [];
	if (registrar) detailParts.push(`Registrar: ${registrar}`);
	detailParts.push(`Source: ${registrarSource}`);
	return createFinding(CATEGORY, 'Registration details', 'info', detailParts.join('. ') + '.', {
		domain,
		registrar,
		registrarIanaId,
		registrarSource,
	});
}

export interface RdapCheckOptions {
	/** Service binding to bv-whois shim Worker — enables WHOIS fallback for non-RDAP TLDs. */
	whoisBinding?: FetcherLike;
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

	// Extract TLD
	const labels = domain.split('.');
	const tld = labels[labels.length - 1];

	// Resolve RDAP server
	const rdapServerUrl = await resolveRdapServer(tld);
	if (!rdapServerUrl) {
		findings.push(
			createFinding(CATEGORY, 'No RDAP server found', 'info', `No RDAP server found for TLD ".${tld}". RDAP data unavailable for this domain.`, {
				domain,
				tld,
			}),
		);
		const whois = await fetchWhoisRegistrar(domain, options.whoisBinding);
		findings.push(buildWhoisFallbackFinding(domain, whois));
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Fetch RDAP domain data
	let rdapData: RdapDomainResponse;
	try {
		const baseUrl = rdapServerUrl.endsWith('/') ? rdapServerUrl : `${rdapServerUrl}/`;
		const rdapUrl = `${baseUrl}domain/${domain}`;
		const resp = await fetch(rdapUrl, {
			redirect: 'manual',
			signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
			headers: { Accept: 'application/rdap+json, application/json' },
		});

		if (!resp.ok) {
			findings.push(
				createFinding(CATEGORY, 'RDAP lookup failed', 'info', `RDAP server returned HTTP ${resp.status} for ${domain}. Registration data unavailable.`, {
					domain,
					httpStatus: resp.status,
				}),
			);
			const whois = await fetchWhoisRegistrar(domain, options.whoisBinding);
			findings.push(buildWhoisFallbackFinding(domain, whois));
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		rdapData = (await resp.json()) as RdapDomainResponse;
	} catch (err) {
		const message = err instanceof Error ? err.message : 'Unknown error';
		findings.push(
			createFinding(CATEGORY, 'RDAP lookup failed', 'info', `RDAP lookup failed for ${domain}: ${message}`, {
				domain,
				error: message,
			}),
		);
		const whois = await fetchWhoisRegistrar(domain, options.whoisBinding);
		findings.push(buildWhoisFallbackFinding(domain, whois));
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Parse registrar
	const registrarEntity = findEntityByRole(rdapData.entities, 'registrar');
	let registrarName = registrarEntity ? extractVcardName(registrarEntity) : null;
	let registrarIanaId = extractRegistrarIanaId(registrarEntity);
	let registrarSource: 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown' = registrarName ? 'rdap' : 'unknown';
	if (!registrarName) {
		const whois = await fetchWhoisRegistrar(domain, options.whoisBinding);
		registrarSource = whoisSourceToRegistrarSource(whois);
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
