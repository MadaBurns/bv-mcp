// SPDX-License-Identifier: BUSL-1.1

import { validateDomain, sanitizeDomain } from '../lib/sanitize';

const TOOL_ALIASES: Record<string, string> = {
	scan: 'scan_domain',
};

export function normalizeToolName(name: string): string {
	const normalized = name.trim().toLowerCase();
	return TOOL_ALIASES[normalized] ?? normalized;
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
	if (typeof args.selector !== 'string' || args.selector.trim().length === 0) {
		return undefined;
	}
	const selector = args.selector.trim().toLowerCase();
	if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(selector) || selector.length > 63) {
		throw new Error('Invalid DKIM selector: must be a valid DNS label (alphanumeric and hyphens, max 63 chars)');
	}
	return selector;
}

const VALID_PROFILES = ['auto', 'mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'] as const;

/** Extract and validate the optional scoring profile parameter. */
export function extractScanProfile(args: Record<string, unknown>): typeof VALID_PROFILES[number] | undefined {
	const profile = args.profile;
	if (profile === undefined || profile === null) return undefined;
	if (typeof profile !== 'string') {
		throw new Error('Invalid profile: must be a string');
	}
	const normalized = profile.trim().toLowerCase();
	if (!(VALID_PROFILES as readonly string[]).includes(normalized)) {
		throw new Error(`Invalid profile: must be one of ${VALID_PROFILES.join(', ')}`);
	}
	return normalized as typeof VALID_PROFILES[number];
}

const VALID_GRADES = new Set(['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'E', 'F']);

/** Extract and validate the optional baseline parameter for compare_baseline. */
export function extractBaseline(args: Record<string, unknown>): Record<string, unknown> {
	const raw = args.baseline;
	if (raw === undefined || raw === null) return {};
	if (typeof raw !== 'object' || Array.isArray(raw)) {
		throw new Error('Invalid baseline: must be an object');
	}
	const b = raw as Record<string, unknown>;
	const result: Record<string, unknown> = {};
	if (b.grade !== undefined) {
		if (typeof b.grade !== 'string' || !VALID_GRADES.has(b.grade.toUpperCase())) {
			throw new Error('Invalid baseline grade');
		}
		result.grade = b.grade;
	}
	if (b.score !== undefined) {
		if (typeof b.score !== 'number' || b.score < 0 || b.score > 100) {
			throw new Error('Invalid baseline score: must be 0-100');
		}
		result.score = b.score;
	}
	for (const key of ['require_dmarc_enforce', 'require_spf', 'require_dkim', 'require_dnssec', 'require_mta_sts', 'require_caa'] as const) {
		if (b[key] !== undefined) {
			if (typeof b[key] !== 'boolean') {
				throw new Error(`Invalid baseline ${key}: must be boolean`);
			}
			result[key] = b[key];
		}
	}
	for (const key of ['max_critical_findings', 'max_high_findings'] as const) {
		if (b[key] !== undefined) {
			if (typeof b[key] !== 'number' || b[key]! < 0 || !Number.isInteger(b[key])) {
				throw new Error(`Invalid baseline ${key}: must be a non-negative integer`);
			}
			result[key] = b[key];
		}
	}
	return result;
}

export function extractExplainFindingArgs(args: Record<string, unknown>): {
	checkType: string;
	status: string;
	details?: string;
} {
	const checkType = args.checkType;
	const status = args.status;
	if (typeof checkType !== 'string' || typeof status !== 'string') {
		throw new Error('Missing required parameters: checkType and status');
	}
	if (checkType.length > 100) {
		throw new Error('Invalid checkType: must be <= 100 characters');
	}
	if (status.length > 500) {
		throw new Error('Invalid status: must be <= 500 characters');
	}
	const details = typeof args.details === 'string' ? args.details : undefined;
	if (details && details.length > 2000) {
		throw new Error('Invalid details: must be <= 2000 characters');
	}
	return { checkType, status, details };
}