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
	/** True when the registry explicitly indicated no record exists. */
	notFound: boolean;
	/** True when the registry returned data but redacted the registrar (e.g. DENIC). */
	redacted: boolean;
}

/**
 * Parse a WHOIS response into a structured result.
 *
 * Heuristics:
 *  - Prefer `Registrar:` over `Sponsoring Registrar:` (modern ICANN template wins).
 *  - Treat `% No match`, `No match for domain`, or similar as not-found.
 *  - Treat DENIC's plaintext disclosure-blocked notice as redacted.
 *  - Only consider the first MAX_RESPONSE_BYTES (defense against flood).
 *  - Only match lines that BEGIN with the key (after optional whitespace) — avoids
 *    URLs / TOS boilerplate where the key appears mid-line.
 */
export function parseWhoisResponse(input: string): WhoisParseResult {
	const truncated = input.length > MAX_RESPONSE_BYTES ? input.slice(0, MAX_RESPONSE_BYTES) : input;

	const notFound = /(^|\n)\s*(no match for|not found|no entries found|no data found|domain not found)/i.test(truncated);
	const denicRedacted = /denic whois service.*doesn't disclose|disclose any information concerning the domain holder/i.test(truncated);

	let registrar: string | null = null;
	let sponsoring: string | null = null;

	for (const rawLine of truncated.split('\n')) {
		const line = rawLine.replace(/\r$/, '');
		const trimmed = line.replace(/^\s+/, '');

		const regMatch = trimmed.match(/^Registrar:\s*(.+?)\s*$/i);
		if (regMatch && !registrar) {
			registrar = regMatch[1];
			continue;
		}

		const sponMatch = trimmed.match(/^Sponsoring Registrar:\s*(.+?)\s*$/i);
		if (sponMatch && !sponsoring) {
			sponsoring = sponMatch[1];
		}
	}

	const resolved = registrar ?? sponsoring;

	return {
		registrar: resolved,
		notFound: notFound && !resolved,
		redacted: !resolved && denicRedacted,
	};
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
