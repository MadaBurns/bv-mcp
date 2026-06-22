// SPDX-License-Identifier: BUSL-1.1

import { sanitizeInput } from './sanitize';

const MARKDOWN_SYNTAX = /[`*_#[\]()>|<]/g;
const ANSI_ESCAPE = /(?:\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~])/g;
const CONTROL_BYTES = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g;
const UNICODE_STEALTH = /[\u061C\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

/**
 * Characters that can inject HTML or dangerous markdown constructs.
 * Excludes `_` (common in DNS names like `_dmarc`, `_mta-sts`) and
 * `()` (used in natural-language detail text) which are safe in finding details.
 */
const DNS_DATA_UNSAFE = /[`*#[\]>|<]/g;

/**
 * Sanitize DNS-sourced data before it enters finding detail strings.
 * NFKC-normalizes confusable forms, strips ANSI/C0/C1/bidi/zero-width control
 * vectors, replaces HTML/markdown injection characters, and does NOT truncate —
 * DNS data in findings can be longer than display output.
 */
export function sanitizeDnsData(input: string): string {
	return input
		.normalize('NFKC')
		.replace(ANSI_ESCAPE, '')
		.replace(CONTROL_BYTES, '')
		.replace(UNICODE_STEALTH, '')
		.replace(DNS_DATA_UNSAFE, ' ')
		.replace(/\s+/g, ' ')
		.trim();
}

export function sanitizeOutputText(input: string, maxLength = 240): string {
	const trimmed = sanitizeInput(input, maxLength * 2)
		.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
		.replace(MARKDOWN_SYNTAX, ' ')
		.replace(/\s+/g, ' ')
		.trim();

	if (trimmed.length <= maxLength) {
		return trimmed;
	}

	return `${trimmed.slice(0, maxLength - 3).trimEnd()}...`;
}