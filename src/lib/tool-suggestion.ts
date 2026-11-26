// SPDX-License-Identifier: BUSL-1.1

/**
 * Call-time recovery text for an unknown tool name. Suggestions come ONLY from the tools the
 * anonymous `tools/list` shows (internal-only tools are never offered), so an unknown-tool
 * reply cannot be used to probe for hidden tools.
 */

import { isInternalOnlyTool } from './config';
import { TOOLS } from '../schemas/tool-definitions';

const MAX_SUGGESTIONS = 3;
/** Longest name worth comparing; anything longer is not a typo of a real tool. */
const MAX_COMPARED_LENGTH = 64;
const CHECK_PREFIX = 'check_';

function editDistance(a: string, b: string): number {
	let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
	for (let i = 1; i <= a.length; i++) {
		const row = [i];
		for (let j = 1; j <= b.length; j++) {
			row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
		}
		prev = row;
	}
	return prev[b.length];
}

function stripCheckPrefix(name: string): string {
	return name.startsWith(CHECK_PREFIX) ? name.slice(CHECK_PREFIX.length) : name;
}

/** Up to three public tool names close to `name` (small edit distance, or a missing/extra `check_` prefix). */
export function suggestToolNames(name: string): string[] {
	const needle = name.trim().toLowerCase();
	if (needle.length === 0 || needle.length > MAX_COMPARED_LENGTH) return [];
	const bareNeedle = stripCheckPrefix(needle);
	const maxDistance = needle.length >= 12 ? 3 : 2;
	const scored: Array<{ name: string; distance: number }> = [];
	for (const tool of TOOLS) {
		if (isInternalOnlyTool(tool.name) || tool.name === needle) continue;
		const prefixOnly = bareNeedle.length > 0 && stripCheckPrefix(tool.name) === bareNeedle;
		const distance = prefixOnly ? 0 : editDistance(needle, tool.name);
		if (prefixOnly || distance <= maxDistance) scored.push({ name: tool.name, distance });
	}
	scored.sort((x, y) => x.distance - y.distance || x.name.localeCompare(y.name));
	return scored.slice(0, MAX_SUGGESTIONS).map((s) => s.name);
}

/** Full unknown-tool message; always starts `Unknown tool:` (request telemetry matches on it). */
export function buildUnknownToolMessage(name: string): string {
	const base = `Unknown tool: ${name}. Call tools/list to see the available tools.`;
	const suggestions = suggestToolNames(name);
	return suggestions.length > 0 ? `${base} Did you mean: ${suggestions.join(', ')}?` : base;
}
