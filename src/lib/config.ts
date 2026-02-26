/**
 * Centralized configuration for domain normalization and validation.
 */
export const BLOCKED_SUFFIXES = [
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
export const BLOCKED_HOSTS = ['localhost', 'localhost.localdomain'];
export const BLOCKED_IP_PATTERNS = [
	/^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^169\.254\.[0-9]{1,3}\.[0-9]{1,3}$/,
	/^0\.0\.0\.0$/,
	/^::1$/,
	/^fc00:/i,
	/^fd[0-9a-f]{2}:/i,
	/^fe80:/i,
];
export const BLOCKED_DNS_REBINDING = ['.nip.io', '.sslip.io', '.xip.io', '.nip.direct'];
export const MAX_DOMAIN_LENGTH = 253;
export const MAX_LABEL_LENGTH = 63;
export const LABEL_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;
