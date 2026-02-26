import * as punycode from 'punycode/';
import {
    BLOCKED_SUFFIXES,
    BLOCKED_HOSTS,
    BLOCKED_IP_PATTERNS,
    BLOCKED_DNS_REBINDING,
    MAX_DOMAIN_LENGTH,
    MAX_LABEL_LENGTH,
    LABEL_REGEX,
} from '../../lib/config';

export interface ValidationResult {
	valid: boolean;
	error?: string;
}

/**
 * Validate and sanitize a domain name for DNS queries.
 * Rejects localhost, private/reserved TLDs, IP addresses, and malformed domains.
 */
export function validateDomain(input: string): ValidationResult {
	if (!input || typeof input !== 'string') {
		return { valid: false, error: 'Domain name is required' };
	}
	const invisiblePattern = /[\p{C}\p{Zl}\p{Zp}\u200B-\u200D\uFEFF]/gu;
	if (invisiblePattern.test(input)) {
		return { valid: false, error: 'Domain contains invalid Unicode or cannot be converted to ASCII' };
	}
	const cleaned = input.replace(invisiblePattern, '').trim();
	if (cleaned.length === 0) {
		return { valid: false, error: 'Domain name is required' };
	}
	let domain = cleaned.normalize('NFC').toLowerCase();
	if (domain.endsWith('.')) domain = domain.slice(0, -1);
	let asciiDomain: string;
	try {
		asciiDomain = punycode.toASCII(domain);
	} catch {
		return { valid: false, error: 'Domain contains invalid Unicode or cannot be converted to ASCII' };
	}
	if (asciiDomain.length > MAX_DOMAIN_LENGTH) {
		return { valid: false, error: `Domain exceeds maximum length of ${MAX_DOMAIN_LENGTH} characters` };
	}
	if (BLOCKED_HOSTS.includes(asciiDomain)) {
		return { valid: false, error: `Domain "${asciiDomain}" is not allowed: reserved hostname` };
	}
	for (const suffix of BLOCKED_SUFFIXES) {
		if (asciiDomain === suffix.slice(1) || asciiDomain.endsWith(suffix)) {
			return { valid: false, error: `Domain "${asciiDomain}" is not allowed: reserved TLD "${suffix}"` };
		}
	}
	for (const pattern of BLOCKED_IP_PATTERNS) {
		if (pattern.test(asciiDomain)) {
			return { valid: false, error: `IP addresses are not allowed: "${asciiDomain}"` };
		}
	}
	for (const suffix of BLOCKED_DNS_REBINDING) {
		if (asciiDomain === suffix.slice(1) || asciiDomain.endsWith(suffix)) {
			return { valid: false, error: 'Domain uses a DNS rebinding service and is not allowed' };
		}
	}
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
}
