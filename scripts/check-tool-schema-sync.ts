// SPDX-License-Identifier: BUSL-1.1

/**
 * Structural TOOL_DEFS <-> TOOL_SCHEMA_MAP parity check.
 *
 * WHY A SCRIPT AND NOT A REGEX
 * This check used to be an inline `node -e` one-liner in .claude/settings.json
 * that scraped source text, pulling the TOOL_DEFS body out with
 * /TOOL_DEFS[^{]*\{([\s\S]+?)^\};/m and falling back to '' when that failed.
 * When the terminator changed from `};` to `} satisfies Record<string, ToolDef>;`
 * the match returned null, the fallback produced an empty body, zero keys were
 * extracted, and the check reported all 85 registered tools as missing from
 * TOOL_DEFS. The registry was untouched; only the parser broke.
 *
 * Two lessons are baked in. Resolve the registries by IMPORTING them, the way
 * scripts/tool-surface-tokens.ts already does, so the check sees real runtime
 * keys and is immune to annotation syntax. And treat an empty registry as a
 * hard failure rather than as evidence of absence, so a future loading problem
 * is reported as a loading problem instead of as 85 phantom findings.
 *
 * Usage:
 *   npx tsx scripts/check-tool-schema-sync.ts            # CI: exit 1 on drift
 *   npx tsx scripts/check-tool-schema-sync.ts --hook     # Claude Code hook JSON
 */

import { TOOL_SCHEMA_MAP } from '../src/schemas/tool-args';
import { TOOLS } from '../src/schemas/tool-definitions';

function collectProblems(): string[] {
	const registered = new Set(TOOLS.map((tool) => tool.name));
	const schemas = new Set(Object.keys(TOOL_SCHEMA_MAP));
	const problems: string[] = [];

	// Fail loud on an empty side. An empty set is a load failure, never proof
	// that every tool vanished — conflating the two is the defect this replaces.
	if (registered.size === 0) {
		problems.push('TOOL_DEFS resolved to zero tools — this is a checker fault, not tool drift');
	}
	if (schemas.size === 0) {
		problems.push('TOOL_SCHEMA_MAP resolved to zero schemas — this is a checker fault, not tool drift');
	}
	if (problems.length > 0) return problems;

	const missingFromDefs = [...schemas].filter((name) => !registered.has(name));
	const missingFromSchemas = [...registered].filter((name) => !schemas.has(name));

	if (missingFromDefs.length > 0) {
		problems.push(`In TOOL_SCHEMA_MAP but not TOOL_DEFS: ${missingFromDefs.join(', ')}`);
	}
	if (missingFromSchemas.length > 0) {
		problems.push(`In TOOL_DEFS but not TOOL_SCHEMA_MAP: ${missingFromSchemas.join(', ')}`);
	}
	return problems;
}

function main(): void {
	const hookMode = process.argv.includes('--hook');
	const problems = collectProblems();

	if (problems.length === 0) {
		if (!hookMode) {
			console.log(`TOOL_DEFS <-> TOOL_SCHEMA_MAP in sync (${TOOLS.length} tools).`);
		}
		return;
	}

	const message = problems.join('. ');
	if (hookMode) {
		// Claude Code reads a JSON envelope on stdout; exit 0 so the envelope,
		// not the exit code, carries the verdict.
		console.log(JSON.stringify({ continue: false, stopReason: message }));
		return;
	}
	console.error(message);
	process.exit(1);
}

main();
