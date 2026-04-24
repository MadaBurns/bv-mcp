// SPDX-License-Identifier: BUSL-1.1

import { ZodError } from 'zod';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import { logEvent } from '../lib/log';
import { TOOL_SCHEMA_MAP } from '../schemas/tool-args';
import type { OutputFormat, Profile } from '../schemas/primitives';

/**
 * Time-boxed telemetry: record what inputs clients send that get rejected.
 * Added 2026-04-25 to diagnose explain_finding's 27% error rate (10/37 calls).
 * Remove once 7 days of data has been reviewed and the root cause is known.
 */
function logExplainFindingRejection(args: Record<string, unknown>, err: ZodError): void {
	const issue = err.issues[0];
	const path = issue.path.join('.');
	const received = args[path];
	let rejectedValue: string;
	if (received === undefined) rejectedValue = '<missing>';
	else if (received === null) rejectedValue = '<null>';
	else if (typeof received === 'string') rejectedValue = received.replace(/[\x00-\x1F\x7F]/g, '?').slice(0, 64);
	else rejectedValue = typeof received;
	logEvent({
		timestamp: new Date().toISOString(),
		severity: 'info',
		tool: 'explain_finding',
		result: 'explain_finding_rejected',
		details: {
			rejectedField: path,
			rejectedValue,
			issueCode: issue.code,
		},
	});
}

export type { OutputFormat };

const TOOL_ALIASES: Record<string, string> = {
	scan: 'scan_domain',
};

export function normalizeToolName(name: string): string {
	const normalized = name.trim().toLowerCase();
	return TOOL_ALIASES[normalized] ?? normalized;
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
			if (toolName === 'explain_finding') {
				logExplainFindingRejection(args, err);
			}
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
