// SPDX-License-Identifier: BUSL-1.1

import { sanitizeInput } from './sanitize';

const MARKDOWN_SYNTAX = /[`*_#[\]()>|]/g;

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