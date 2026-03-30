// SPDX-License-Identifier: BUSL-1.1

// For IDN/Unicode normalization
import * as punycode from 'punycode/';
// Centralized normalization config
import {
	BLOCKED_SUFFIXES,
	BLOCKED_HOSTS,
	BLOCKED_IP_PATTERNS,
	BLOCKED_DNS_REBINDING,
	MAX_DOMAIN_LENGTH,
	MAX_LABEL_LENGTH,
	LABEL_REGEX,
} from './config';
/**
 * Input sanitization and validation utilities for the DNS Security MCP Server.
 * Handles domain validation, input cleaning, and MCP error response helpers.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

export interface ValidationResult {
	valid: boolean;
	error?: string;
}

/**
 * Parse a numeric IPv4 segment using decimal, octal, or hex notation.
 * Returns null when the token is not a numeric IP segment.
 */
function parseIpv4NumberToken(token: string): number | null {
	if (!token) return null;

	let radix = 10;
	let digits = token;
	if (/^0x[0-9a-f]+$/i.test(token)) {
		radix = 16;
		digits = token.slice(2);
	} else if (/^0[0-7]+$/.test(token) && token.length > 1) {
		radix = 8;
	}

	if (digits.length === 0) return null;
	const value = Number.parseInt(digits, radix);
	if (!Number.isFinite(value) || value < 0) return null;
	return value;
}

/**
 * Canonicalize IPv4 literals that may use short/octal/hex forms.
 * Returns null when input is not an IPv4 host literal candidate.
 */
function canonicalizeIpv4Literal(input: string): string | null {
	if (!/^[0-9a-fx.]+$/i.test(input)) return null;

	const parts = input.split('.');
	if (parts.length < 1 || parts.length > 4) return null;
	if (parts.some((part) => part.length === 0)) return null;

	const values: number[] = [];
	for (const part of parts) {
		const parsed = parseIpv4NumberToken(part);
		if (parsed === null) return null;
		values.push(parsed);
	}

	let ipAsUint32 = 0;
	if (values.length === 1) {
		if (values[0] > 0xffffffff) return null;
		ipAsUint32 = values[0] >>> 0;
	} else if (values.length === 2) {
		if (values[0] > 0xff || values[1] > 0xffffff) return null;
		ipAsUint32 = ((values[0] << 24) | values[1]) >>> 0;
	} else if (values.length === 3) {
		if (values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff) return null;
		ipAsUint32 = ((values[0] << 24) | (values[1] << 16) | values[2]) >>> 0;
	} else {
		if (values.some((value) => value > 0xff)) return null;
		ipAsUint32 = ((values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]) >>> 0;
	}

	const oct1 = (ipAsUint32 >>> 24) & 0xff;
	const oct2 = (ipAsUint32 >>> 16) & 0xff;
	const oct3 = (ipAsUint32 >>> 8) & 0xff;
	const oct4 = ipAsUint32 & 0xff;
	return `${oct1}.${oct2}.${oct3}.${oct4}`;
}

/**
 * Validate and sanitize a domain name for DNS queries.
 * Rejects localhost, private/reserved TLDs, IP addresses, and malformed domains.
 */

export function validateDomain(input: string): ValidationResult {
	if (!input || typeof input !== 'string') {
		return { valid: false, error: 'Domain name is required' };
	}

	// Check for invisible/non-printable Unicode (except space, dot, hyphen)
	const invisiblePattern = /[\p{C}\p{Zl}\p{Zp}\u200B-\u200D\uFEFF]/gu;
	if (invisiblePattern.test(input)) {
		return { valid: false, error: 'Domain contains invalid Unicode or cannot be converted to ASCII' };
	}
	const cleaned = input.replace(invisiblePattern, '').trim();
	if (cleaned.length === 0) {
		return { valid: false, error: 'Domain name is required' };
	}

	// Normalize Unicode to NFC, lowercase, remove trailing dot
	let domain = cleaned.normalize('NFC').toLowerCase();
	if (domain.endsWith('.')) domain = domain.slice(0, -1);

	// Convert Unicode/emoji/IDN to punycode for validation
	let asciiDomain: string;
	try {
		asciiDomain = punycode.toASCII(domain);
	} catch {
		return { valid: false, error: 'Domain contains invalid Unicode or cannot be converted to ASCII' };
	}

	if (asciiDomain.length > MAX_DOMAIN_LENGTH) {
		return { valid: false, error: `Domain exceeds maximum length of ${MAX_DOMAIN_LENGTH} characters` };
	}

	// Check blocked exact hostnames
	if (BLOCKED_HOSTS.includes(asciiDomain)) {
		return { valid: false, error: `Domain "${asciiDomain}" is not allowed: reserved hostname` };
	}

	// Check blocked suffixes
	for (const suffix of BLOCKED_SUFFIXES) {
		if (asciiDomain === suffix.slice(1) || asciiDomain.endsWith(suffix)) {
			return { valid: false, error: `Domain "${asciiDomain}" is not allowed: reserved TLD "${suffix}"` };
		}
	}

	// Canonicalize non-standard IPv4 literals (e.g. 127.1, 0177.0.0.1)
	// and reject all IP literal forms (public, private, and special).
	const canonicalIpv4 = canonicalizeIpv4Literal(asciiDomain);
	if (canonicalIpv4) {
		return { valid: false, error: `IP addresses are not allowed: "${asciiDomain}"` };
	}

	// Reject dotted numeric host literals that are IPv4-like but malformed/out-of-range.
	if (/^\d+(?:\.\d+){1,3}$/.test(asciiDomain)) {
		return { valid: false, error: `IP addresses are not allowed: "${asciiDomain}"` };
	}

	// Check if it looks like an IP address (blocked)
	for (const pattern of BLOCKED_IP_PATTERNS) {
		if (pattern.test(asciiDomain)) {
			return { valid: false, error: `IP addresses are not allowed: "${asciiDomain}"` };
		}
	}

	// Check for DNS rebinding services
	for (const suffix of BLOCKED_DNS_REBINDING) {
		if (asciiDomain === suffix.slice(1) || asciiDomain.endsWith(suffix)) {
			return { valid: false, error: 'Domain uses a DNS rebinding service and is not allowed' };
		}
	}

	// Validate domain label structure (punycode labels)
	const labels = asciiDomain.split('.');
	if (labels.length < 2) {
		return { valid: false, error: 'Domain must have at least two labels (e.g., example.com)' };
	}
	for (const label of labels) {
		if (label.length === 0) {
			return { valid: false, error: 'Domain contains empty label (consecutive dots)' };
		}
		// Strip HTML/script tags from label before including in error messages
		const safeLabel = label.replace(/[<>]/g, '').slice(0, 63);
		if (label.length > MAX_LABEL_LENGTH) {
			return { valid: false, error: `Label "${safeLabel}" exceeds maximum length of ${MAX_LABEL_LENGTH} characters` };
		}
		if (!LABEL_REGEX.test(label)) {
			return { valid: false, error: `Label "${safeLabel}" contains invalid characters` };
		}
	}

	return { valid: true };
}

/**
 * Sanitize a domain string: trim, lowercase, remove trailing dot.
 * Call validateDomain first to ensure the domain is valid.
 */
export function sanitizeDomain(input: string): string {
	// Remove invisible/non-printable Unicode (except space, dot, hyphen)
	const cleaned = input.replace(/[\p{C}\p{Zl}\p{Zp}\u200B-\u200D\uFEFF]/gu, '').trim();
	if (cleaned.length === 0) return '';
	let domain = cleaned.normalize('NFC').toLowerCase();
	if (domain.endsWith('.')) domain = domain.slice(0, -1);
	// Convert Unicode/emoji/IDN to punycode for DNS queries
	try {
		return punycode.toASCII(domain);
	} catch {
		return '';
	}
}

/**
 * Sanitize arbitrary text input for safe logging/display.
 * Removes control characters except newlines and tabs, and truncates length.
 */
export function sanitizeInput(input: string, maxLength = 500): string {
	if (typeof input !== 'string') return '';
	const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
	return sanitized.slice(0, maxLength);
}


