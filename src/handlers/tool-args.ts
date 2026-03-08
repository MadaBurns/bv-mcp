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
	return sanitizeDomain(domain);
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
	return {
		checkType,
		status,
		details: typeof args.details === 'string' ? args.details : undefined,
	};
}