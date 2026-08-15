// SPDX-License-Identifier: BUSL-1.1

import { extractFormat, type OutputFormat } from './tool-args';

/** Known interactive LLM client types that benefit from compact output. */
const INTERACTIVE_CLIENTS = new Set([
	'claude_mobile',
	'claude_code',
	'cursor',
	'vscode',
	'claude_desktop',
	'claude_connector',
	'windsurf',
]);

/** Resolve explicit output format, falling back to the interactive-client default. */
export function resolveToolOutputFormat(args: Record<string, unknown>, clientType?: string): OutputFormat {
	const explicit = extractFormat(args);
	if (explicit) return explicit;
	return INTERACTIVE_CLIENTS.has(clientType ?? '') ? 'compact' : 'full';
}
