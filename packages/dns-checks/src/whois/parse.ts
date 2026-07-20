// SPDX-License-Identifier: BUSL-1.1
/**
 * WHOIS response parser and IANA referral parser.
 *
 * Pure functions — no I/O, no transport. The transport (TCP/43 via
 * `cloudflare:sockets` or an HTTPS shim) is composed elsewhere; this module
 * is the spec-locked piece of the WHOIS fallback path.
 */

/** Cap parsing input size to defend against flood responses. */
export const MAX_RESPONSE_BYTES = 64 * 1024;

export interface WhoisParseResult {
	registrar: string | null;
	registrarIanaId: string | null;
	/** Raw registration/creation date string as found (label variants normalised at the surface). */
	creationDate: string | null;
	/** Raw last-updated/last-modified date string as found. */
	updatedDate: string | null;
	/** Raw expiry/expiration date string as found. */
	expiryDate: string | null;
	/** Registrant organisation/name string as found (may be a privacy-proxy name). */
	registrantOrg: string | null;
	/** True when the registrant record is redacted behind a privacy/proxy service. */
	registrantPrivacy: boolean;
	/** True when the registry explicitly indicated no record exists. */
	notFound: boolean;
	/** True when the registry returned data but redacted the registrar (e.g. DENIC). */
	redacted: boolean;
}

/**
 * Registration-date label variants seen across gTLD/ccTLD WHOIS templates,
 * ordered specific → generic. The matcher (`matchLabelledValue`) returns the
 * first label with any line hit, so a specific `Creation Date` wins over a bare
 * `Created`. Anchored strictly at line start after a colon, so a label can't
 * false-match a longer field name (`^Created:` never matches `Created On:`).
 */
const CREATION_DATE_LABELS = [
	'Creation Date',
	'Created On',
	'Created Date',
	'Domain Registration Date',
	'Original Created', // .nz
	'Registered On',
	'Registered on',
	'Created', // includes lowercase `created:` via the /i flag (RIPE-style ccTLD)
	'Registered',
] as const;

const UPDATED_DATE_LABELS = [
	'Updated Date',
	'Last Modified',
	'Last Updated',
	'Last Update',
	'Updated On',
	'Updated', // includes lowercase `changed:` below
	'changed',
	'modified',
] as const;

const EXPIRY_DATE_LABELS = [
	'Registry Expiry Date',
	'Registrar Registration Expiration Date',
	'Expiration Date',
	'Expiry Date',
	'Expire Date',
	'Expires On',
	'Expires', // includes lowercase `expires:` via the /i flag (RIPE-style ccTLD)
	'paid-till',
] as const;

const REGISTRANT_ORG_LABELS = [
	'Registrant Organization',
	'Registrant Organisation',
	'Registrant Org',
	'Registrant Name',
	'Registrant',
] as const;

/** Privacy/proxy registrant markers — the redaction states the RDAP fallback must surface. */
const REGISTRANT_PRIVACY_RE = /redacted for privacy|withheld for privacy|privacy service|data protected/i;

/** Longest usable value length per field — keeps values under the RDAP tool's Zod caps (dates 64, org 256). */
const MAX_DATE_LEN = 64;
const MAX_ORG_LEN = 256;

function escapeWhoisLabel(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Return the first non-empty value for any of `labels` (label priority order),
 * matching `^Label:\s*<value>$` line-anchored + case-insensitively. Pure.
 */
function matchLabelledValue(lines: readonly string[], labels: readonly string[], maxLen: number): string | null {
	for (const label of labels) {
		const re = new RegExp(`^${escapeWhoisLabel(label)}\\s*:\\s*(.+?)\\s*$`, 'i');
		for (const raw of lines) {
			const line = raw.replace(/\r$/, '').replace(/^\s+/, '');
			const m = line.match(re);
			if (m) {
				const value = m[1].trim();
				if (value.length > 0) return value.length > maxLen ? value.slice(0, maxLen) : value;
			}
		}
	}
	return null;
}

/**
 * Parse a WHOIS response into a structured result.
 *
 * Heuristics:
 *  - Prefer `Registrar: <value>` (modern ICANN single-line template).
 *  - Then Nominet's `Registrar:` label-only followed by indented value on the next line.
 *  - Then `Sponsoring Registrar:` (legacy alias).
 *  - Treat `% No match`, `No match for domain`, or similar as not-found.
 *  - Treat DENIC's plaintext disclosure-blocked notice as redacted.
 *  - Only consider the first MAX_RESPONSE_BYTES (defense against flood).
 *  - Only match lines that BEGIN with the key (after optional whitespace) — avoids
 *    URLs / TOS boilerplate where the key appears mid-line.
 */
export function parseWhoisResponse(input: string): WhoisParseResult {
	const truncated = input.length > MAX_RESPONSE_BYTES ? input.slice(0, MAX_RESPONSE_BYTES) : input;

	const notFound = /(^|\n)\s*(no match for|not found|no entries found|no data found|domain not found)/i.test(truncated);
	const denicRedacted =
		/denic whois service.*doesn't disclose|disclose any information concerning the domain holder/i.test(truncated) ||
		/requests of this client are not permitted|ip address used to perform the query\s+is not authorised|exceeded the established limit for\s+queries/i.test(
			truncated,
		);

	let registrar: string | null = null;
	let registrarName: string | null = null;
	let registrarOrganization: string | null = null;
	let registrarIanaId: string | null = null;
	let sponsoring: string | null = null;
	let authorizedAgency: string | null = null;

	const lines = truncated.split('\n');
	for (let i = 0; i < lines.length; i++) {
		const trimmed = lines[i].replace(/\r$/, '').replace(/^\s+/, '');

		// Modern ICANN: `Registrar: <value>`
		const regMatch = trimmed.match(/^Registrar:\s*(.+?)\s*$/i);
		if (regMatch && !registrar) {
			registrar = stripNominetTag(regMatch[1]);
			continue;
		}

		const regNameMatch = trimmed.match(/^Registrar Name:\s*(.+?)\s*$/i);
		if (regNameMatch && !registrarName) {
			registrarName = stripNominetTag(regNameMatch[1]);
			continue;
		}

		const regOrgMatch = trimmed.match(/^Registrar Organization:\s*(.+?)\s*$/i);
		if (regOrgMatch && !registrarOrganization) {
			registrarOrganization = stripNominetTag(regOrgMatch[1]);
			continue;
		}

		const ianaIdMatch = trimmed.match(/^Registrar IANA ID:\s*(\S+)\s*$/i);
		if (ianaIdMatch && !registrarIanaId) {
			registrarIanaId = ianaIdMatch[1].trim();
			continue;
		}

		// Nominet-style: `Registrar:` (label only) — value is on the next non-empty line.
		// Anchor strictly on `/^Registrar:\s*$/i` so partial labels like `Last Registrar Update:`
		// don't false-match (they have text before the colon and fail the leading-anchor).
		if (!registrar && /^Registrar:\s*$/i.test(trimmed)) {
			for (let j = i + 1; j < lines.length; j++) {
				const nextRaw = lines[j].replace(/\r$/, '');
				const next = nextRaw.replace(/^\s+/, '').replace(/\s+$/, '');
				if (next.length === 0) continue;
				// Reject continuation lines that look like a structured `Label:` or
				// `Label: value` field (e.g. EURid's `Name: NETIM`, `Organization: ...`,
				// `Website: ...`). These are sub-fields of a registrar block, not the
				// registrar name itself. Emitting `Name: NETIM` verbatim as the
				// registrar is the bug we observed against `anthropic.eu`. The
				// fallback chain (registrarName / sponsoring / registrarOrganization /
				// authorizedAgency) still scans the whole response and resolves the
				// proper value when present elsewhere; when nothing else matches we
				// correctly return null rather than a half-parsed string.
				if (/^[A-Za-z][A-Za-z][\w .-]*:/.test(next)) break;
				registrar = stripNominetTag(next);
				break;
			}
			continue;
		}

		if (!registrar && (/^Registrar\s*$/i.test(trimmed) || /^\*\*\s*Registrar:\s*$/i.test(trimmed))) {
			let sectionOrganization: string | null = null;
			let sectionName: string | null = null;
			for (let j = i + 1; j < lines.length; j++) {
				const next = lines[j].replace(/\r$/, '').replace(/^\s+/, '').replace(/\s+$/, '');
				if (next.length === 0) break;
				const orgMatch = next.match(/^Organization(?: Name)?\s*:\s*(.+?)\s*$/i);
				if (orgMatch && !sectionOrganization) {
					sectionOrganization = stripNominetTag(orgMatch[1]);
					continue;
				}
				const nameMatch = next.match(/^Name\s*:\s*(.+?)\s*$/i);
				if (nameMatch && !sectionName) {
					sectionName = stripNominetTag(nameMatch[1]);
					continue;
				}
				if (/^[A-Za-z][A-Za-z\s]+$/.test(next) && !/^DNSSEC$/i.test(next)) break;
			}
			registrar = sectionOrganization ?? sectionName;
			if (registrar) continue;
		}

		const sponMatch = trimmed.match(/^Sponsoring Registrar:\s*(.+?)\s*$/i);
		if (sponMatch && !sponsoring) {
			sponsoring = stripNominetTag(sponMatch[1]);
			continue;
		}

		const authorizedAgencyMatch = trimmed.match(/^Authorized Agency\s*:\s*(.+?)\s*$/i);
		if (authorizedAgencyMatch && !authorizedAgency) {
			authorizedAgency = stripNominetTag(authorizedAgencyMatch[1]);
		}
	}

	const resolved = registrar ?? registrarName ?? sponsoring ?? registrarOrganization ?? authorizedAgency;

	const creationDate = matchLabelledValue(lines, CREATION_DATE_LABELS, MAX_DATE_LEN);
	const updatedDate = matchLabelledValue(lines, UPDATED_DATE_LABELS, MAX_DATE_LEN);
	const expiryDate = matchLabelledValue(lines, EXPIRY_DATE_LABELS, MAX_DATE_LEN);
	const registrantOrg = matchLabelledValue(lines, REGISTRANT_ORG_LABELS, MAX_ORG_LEN);
	const registrantPrivacy = REGISTRANT_PRIVACY_RE.test(truncated);

	return {
		registrar: resolved,
		registrarIanaId,
		creationDate,
		updatedDate,
		expiryDate,
		registrantOrg,
		registrantPrivacy,
		notFound: notFound && !resolved,
		redacted: !resolved && denicRedacted,
	};
}

/**
 * Nominet appends a registrar tag like ` [Tag = MARKMONITOR]` to the registrar
 * name; it's not part of the legal name. Other registries don't use this.
 * No-op when no tag is present.
 */
function stripNominetTag(value: string): string {
	return value.replace(/\s*\[Tag\s*=\s*[^\]]*\]\s*$/i, '').trim();
}

/**
 * Parse the response from `whois.iana.org` to extract the authoritative
 * registry WHOIS server for a TLD.
 *
 * Returns the hostname (no port, no scheme), or null when:
 *   - The TLD has no IANA record ("returned 0 objects" message)
 *   - The response lacks a `whois:` line
 */
export function parseIanaReferral(input: string): string | null {
	const truncated = input.length > MAX_RESPONSE_BYTES ? input.slice(0, MAX_RESPONSE_BYTES) : input;

	for (const rawLine of truncated.split('\n')) {
		const line = rawLine.replace(/\r$/, '');
		const match = line.match(/^whois:\s*(\S+)\s*$/i);
		if (match) {
			return match[1];
		}
	}

	return null;
}
