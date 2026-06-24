// SPDX-License-Identifier: BUSL-1.1

import { sanitizeStructuredString } from '@blackveil/dns-checks/scoring';
import { sanitizeInput } from './sanitize';

const MARKDOWN_SYNTAX = /[`*_#[\]()>|<]/g;

/**
 * Sanitize DNS-sourced data before it enters finding detail strings.
 * NFKC-normalizes confusable forms, strips ANSI/C0/C1/bidi/zero-width control
 * vectors, replaces HTML/markdown injection characters, and does NOT truncate —
 * DNS data in findings can be longer than display output.
 */
export function sanitizeDnsData(input: string): string {
	return sanitizeStructuredString(input);
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