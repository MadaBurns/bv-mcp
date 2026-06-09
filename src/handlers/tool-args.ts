// SPDX-License-Identifier: BUSL-1.1

import { ZodError } from 'zod';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import { TOOL_SCHEMA_MAP } from '../schemas/tool-args';
import type { OutputFormat, Profile } from '../schemas/primitives';

export type { OutputFormat };

/**
 * Tool aliases. A bare `name` is a 1:1 rename. An entry with `injectArgs`
 * additionally supplies default args (used for deprecated names that merged
 * into a parameterized tool — e.g. `generate_spf_record` → `generate` with
 * `artifact: 'spf_record'`). The injected args are FORCED (win over caller
 * args) so the deprecated name's semantics can't be subverted by a conflicting
 * discriminator.
 */
interface ToolAlias {
	name: string;
	injectArgs?: Record<string, unknown>;
}

const TOOL_ALIASES: Record<string, ToolAlias> = {
	scan: { name: 'scan_domain' },
	// Deprecated generate_* tools, merged into `generate` (artifact-discriminated).
	generate_fix_plan: { name: 'generate', injectArgs: { artifact: 'fix_plan' } },
	generate_spf_record: { name: 'generate', injectArgs: { artifact: 'spf_record' } },
	generate_dmarc_record: { name: 'generate', injectArgs: { artifact: 'dmarc_record' } },
	generate_dkim_config: { name: 'generate', injectArgs: { artifact: 'dkim_config' } },
	generate_mta_sts_policy: { name: 'generate', injectArgs: { artifact: 'mta_sts_policy' } },
	generate_rollout_plan: { name: 'generate', injectArgs: { artifact: 'rollout_plan' } },
};

/** Resolve a (possibly aliased) tool name to its canonical name. Name-only — for routing/metrics. */
export function normalizeToolName(name: string): string {
	const normalized = name.trim().toLowerCase();
	return TOOL_ALIASES[normalized]?.name ?? normalized;
}

/**
 * Resolve a tool call through the alias table, injecting any alias-supplied
 * args. Use at the dispatch boundary where args matter; `normalizeToolName`
 * remains the name-only path for routing/analytics.
 */
export function resolveToolAlias(name: string, args: Record<string, unknown>): { name: string; args: Record<string, unknown> } {
	const normalized = name.trim().toLowerCase();
	const alias = TOOL_ALIASES[normalized];
	if (!alias) return { name: normalized, args };
	return { name: alias.name, args: alias.injectArgs ? { ...args, ...alias.injectArgs } : args };
}

/** Return true if the Zod issue represents a missing (undefined) field. */
function isMissingField(issue: ZodError['issues'][number]): boolean {
	// Zod v4: invalid_type when received is undefined (message contains "received undefined")
	return issue.code === 'invalid_type' && issue.message.includes('received undefined');
}

/** Format a ZodError into an error message matching the existing prefix convention. */
function formatZodError(err: ZodError, toolName?: string): string {
	const issue = err.issues[0];
	const path = issue.path.join('.');

	// explain_finding: both checkType and status are required — keep old plural message
	if (toolName === 'explain_finding' && (path === 'checkType' || path === 'status')) {
		if (isMissingField(issue) || issue.code === 'invalid_value') {
			return 'Missing required parameters: checkType and status';
		}
	}

	// validate_fix: domain + check are both required
	if (toolName === 'validate_fix' && path === 'check' && isMissingField(issue)) {
		return 'Missing required parameters: domain and check';
	}

	// analyze_drift: domain + baseline are both required
	if (toolName === 'analyze_drift' && path === 'baseline' && isMissingField(issue)) {
		return 'Missing required parameters: domain and baseline';
	}

	// check_dkim selector: map to the expected "Invalid DKIM selector" prefix
	if (path === 'selector') {
		return `Invalid DKIM selector: ${issue.message}`;
	}

	if (isMissingField(issue)) {
		return `Missing required parameter: ${path}`;
	}
	return `Invalid ${path}: ${issue.message}`;
}

/** Validate tool arguments against the tool's Zod schema. Throws with prefixed error message. */
export function validateToolArgs(toolName: string, args: Record<string, unknown>): Record<string, unknown> {
	const schema = TOOL_SCHEMA_MAP[toolName];
	if (!schema) return args;
	try {
		return schema.parse(args) as Record<string, unknown>;
	} catch (err) {
		if (err instanceof ZodError) {
			throw new Error(formatZodError(err, toolName));
		}
		throw err;
	}
}

export function extractAndValidateDomain(args: Record<string, unknown>): string {
	const domain = args.domain;
	if (typeof domain !== 'string' || domain.trim().length === 0) {
		throw new Error('Missing required parameter: domain');
	}
	const validation = validateDomain(domain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const sanitized = sanitizeDomain(domain);
	if (!sanitized) {
		throw new Error('Domain validation failed: could not normalize domain');
	}
	return sanitized;
}

/*
 * Extraction helpers below operate on the Record<string, unknown> returned by validateToolArgs().
 * Casts such as `as Profile` and `as OutputFormat` are safe — Zod has already validated and
 * normalized these values. The casts exist only because TypeScript cannot narrow `unknown`
 * to a union type without an explicit assertion or redundant runtime check.
 */

/** Extract DKIM selector from pre-validated args. Requires prior validateToolArgs() call. */
export function extractDkimSelector(args: Record<string, unknown>): string | undefined {
	const selector = args.selector;
	if (typeof selector !== 'string' || selector.trim().length === 0) return undefined;
	return selector.trim().toLowerCase();
}

/** Extract scoring profile from pre-validated args. Requires prior validateToolArgs() call. */
export function extractScanProfile(args: Record<string, unknown>): Profile | undefined {
	const profile = args.profile;
	if (typeof profile !== 'string') return undefined;
	return profile as Profile;
}

/** Extract force_refresh flag from pre-validated args. Requires prior validateToolArgs() call. */
export function extractForceRefresh(args: Record<string, unknown>): boolean {
	return (args.force_refresh as boolean) ?? false;
}

/** Extract baseline object from pre-validated args. Requires prior validateToolArgs() call. */
export function extractBaseline(args: Record<string, unknown>): Record<string, unknown> {
	return (args.baseline as Record<string, unknown>) ?? {};
}

/** Extract output format from pre-validated args. Requires prior validateToolArgs() call. */
export function extractFormat(args: Record<string, unknown>): OutputFormat | undefined {
	return (args.format as OutputFormat) ?? undefined;
}

/** Extract DNS record type from pre-validated args. Requires prior validateToolArgs() call. */
export function extractRecordType(args: Record<string, unknown>): string | undefined {
	return (args.record_type as string) ?? undefined;
}

/** Extract include_providers array from pre-validated args. Requires prior validateToolArgs() call. */
export function extractIncludeProviders(args: Record<string, unknown>): string[] | undefined {
	return (args.include_providers as string[]) ?? undefined;
}

/** Extract mx_hosts array from pre-validated args. Requires prior validateToolArgs() call. */
export function extractMxHosts(args: Record<string, unknown>): string[] | undefined {
	return (args.mx_hosts as string[]) ?? undefined;
}

/** Extract explain_finding arguments from pre-validated args. Requires prior validateToolArgs() call. */
export function extractExplainFindingArgs(args: Record<string, unknown>): {
	checkType: string;
	status: string;
	details?: string;
} {
	return {
		checkType: args.checkType as string,
		status: args.status as string,
		details: args.details as string | undefined,
	};
}
