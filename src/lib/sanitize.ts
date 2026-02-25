// For IDN/Unicode normalization
import punycode from 'punycode/';
/**
 * Input sanitization and validation utilities for the DNS Security MCP Server.
 * Handles domain validation, input cleaning, and MCP error response helpers.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

/** Blocked TLDs and suffixes that should never be queried */
const BLOCKED_SUFFIXES = [
	'.local',
	'.localhost',
	'.internal',
	'.example',
	'.invalid',
	'.test',
	'.onion',
	'.lan',
	'.home',
	'.corp',
	'.intranet',
];

/** Blocked exact hostnames */
const BLOCKED_HOSTS = ['localhost', 'localhost.localdomain'];

/** RFC 1918 / loopback patterns to reject in domain names */
const BLOCKED_IP_PATTERNS = [
	/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
	/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
	/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
	/^192\.168\.\d{1,3}\.\d{1,3}$/,
	/^169\.254\.\d{1,3}\.\d{1,3}$/,
	/^0\.0\.0\.0$/,
	/^::1$/,
	/^fc00:/i,
	/^fd[0-9a-f]{2}:/i,
	/^fe80:/i,
];

/** DNS rebinding service suffixes to block */
const BLOCKED_DNS_REBINDING = ['.nip.io', '.sslip.io', '.xip.io', '.nip.direct'];

/** Maximum allowed domain length per RFC 1035 */
const MAX_DOMAIN_LENGTH = 253;

/** Maximum label length per RFC 1035 */
const MAX_LABEL_LENGTH = 63;

/** Valid domain label pattern: alphanumeric and hyphens, no leading/trailing hyphens */
const LABEL_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;

export interface ValidationResult {
	valid: boolean;
	error?: string;
}

/**
 * Validate and sanitize a domain name for DNS queries.
 * Rejects localhost, private/reserved TLDs, IP addresses, and malformed domains.
 */
       if (!input || typeof input !== 'string') {
	       return { valid: false, error: 'Domain name is required' };
       }

       // Remove invisible/non-printable Unicode (except space, dot, hyphen)
       const cleaned = input.replace(/[\p{C}\p{Zl}\p{Zp}\u200B-\u200D\uFEFF]/gu, '').trim();
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
	       if (label.length > MAX_LABEL_LENGTH) {
		       return { valid: false, error: `Label "${label}" exceeds maximum length of ${MAX_LABEL_LENGTH} characters` };
	       }
	       if (!LABEL_REGEX.test(label)) {
		       return { valid: false, error: `Label "${label}" contains invalid characters` };
	       }
       }

	return { valid: true };

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
 * Sanitize a generic user-provided string for safe inclusion in responses.
 * Strips control characters and limits length.
 */
export function sanitizeInput(input: string, maxLength = 500): string {
	if (!input || typeof input !== 'string') return '';
	// Remove control characters (except newline and tab)
	return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, maxLength);
}

/**
 * Create an MCP-compatible error content response.
 * Returns the standard { type: "text", text } format used in MCP tool results.
 */
export function mcpError(message: string): { type: 'text'; text: string } {
	return { type: 'text' as const, text: `Error: ${message}` };
}

/**
 * Create an MCP-compatible success content response.
 */
export function mcpText(text: string): { type: 'text'; text: string } {
	return { type: 'text' as const, text };
}

/**
 * Wrap an async tool handler with standard error handling.
 * Catches errors and returns MCP-formatted error responses.
 */
export async function withErrorHandling<T>(
	fn: () => Promise<T>,
	fallbackMessage = 'An unexpected error occurred',
): Promise<T | { type: 'text'; text: string }> {
	try {
		return await fn();
	} catch (err) {
		const message = err instanceof Error ? err.message : fallbackMessage;
		return mcpError(message);
	}
}
