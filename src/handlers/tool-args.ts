// SPDX-License-Identifier: BUSL-1.1

import { ZodError } from 'zod';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import { TOOL_SCHEMA_MAP } from '../schemas/tool-args';
import type { OutputFormat, Profile } from '../schemas/primitives';

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
		throw new Error(validation.error ?? 'Invalid domain');
	}
	const sanitized = sanitizeDomain(domain);
	if (!sanitized) {
		throw new Error('Domain validation failed: could not normalize domain');
	}
	return sanitized;
}

export function extractDkimSelector(args: Record<string, unknown>): string | undefined {
	const selector = args.selector;
	if (typeof selector !== 'string' || selector.trim().length === 0) return undefined;
	return selector.trim().toLowerCase();
}

export function extractScanProfile(args: Record<string, unknown>): Profile | undefined {
	const profile = args.profile;
	if (typeof profile !== 'string') return undefined;
	return profile as Profile;
}

export function extractForceRefresh(args: Record<string, unknown>): boolean {
	return (args.force_refresh as boolean) ?? false;
}

export function extractBaseline(args: Record<string, unknown>): Record<string, unknown> {
	return (args.baseline as Record<string, unknown>) ?? {};
}

export function extractFormat(args: Record<string, unknown>): OutputFormat | undefined {
	return (args.format as OutputFormat) ?? undefined;
}

export function extractRecordType(args: Record<string, unknown>): string | undefined {
	return (args.record_type as string) ?? undefined;
}

export function extractIncludeProviders(args: Record<string, unknown>): string[] | undefined {
	return (args.include_providers as string[]) ?? undefined;
}

export function extractMxHosts(args: Record<string, unknown>): string[] | undefined {
	return (args.mx_hosts as string[]) ?? undefined;
}

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
