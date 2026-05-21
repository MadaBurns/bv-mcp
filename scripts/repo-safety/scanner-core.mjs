const DEFAULT_POLICY = {
	forbiddenPaths: [],
	sourceExtensions: ['.cjs', '.js', '.json', '.jsonc', '.md', '.mjs', '.py', '.sh', '.sql', '.toml', '.ts', '.tsx', '.yaml', '.yml'],
	allowedEmailDomains: ['example.com', 'example.test', 'example.invalid', 'blackveilsecurity.com'],
	allowedDomainSuffixes: ['example.com', 'example.net', 'example.org', 'example.test', 'example.invalid', 'localhost', 'blackveilsecurity.com'],
	allowedInternalHostnames: [],
	forbiddenClientDomains: [],
	allowedPaths: [],
	allowedPathPrefixes: [],
};

const RULES = [
	{
		id: 'blackveil-api-key',
		pattern: /bv_[A-Za-z0-9_]{30,}/g,
	},
	{
		id: 'private-key-header',
		pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----/g,
	},
	{
		id: 'internal-hostname',
		pattern: /\b[A-Za-z0-9-]+\.(?:internal|corp|lan|localdomain|svc|priv)\b/gi,
	},
	{
		id: 'tenant-marker',
		pattern: /\b(?:tenant-pilot-\d+|tenant-db-tenant-|true-force-scan|X-Emergency-Dispatch)\b/gi,
	},
	{ id: 'customer-marker', pattern: /\bCustomer\s+[A-Z][A-Za-z0-9-]*\s+(?:Corp|Inc|LLC|Ltd|Co)\b/g },
	{ id: 'client-context', pattern: /\b(?:CSC pilot brands|sales-meeting verification|production audit|validation batch)\b/gi },
];

const PUBLIC_IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi;

export function normalizePolicy(policy = {}) {
	return {
		...DEFAULT_POLICY,
		...policy,
		forbiddenPaths: policy.forbiddenPaths ?? DEFAULT_POLICY.forbiddenPaths,
		sourceExtensions: policy.sourceExtensions ?? DEFAULT_POLICY.sourceExtensions,
		allowedEmailDomains: policy.allowedEmailDomains ?? DEFAULT_POLICY.allowedEmailDomains,
		allowedDomainSuffixes: policy.allowedDomainSuffixes ?? DEFAULT_POLICY.allowedDomainSuffixes,
		allowedInternalHostnames: policy.allowedInternalHostnames ?? DEFAULT_POLICY.allowedInternalHostnames,
		forbiddenClientDomains: policy.forbiddenClientDomains ?? DEFAULT_POLICY.forbiddenClientDomains,
		allowedPaths: policy.allowedPaths ?? DEFAULT_POLICY.allowedPaths,
		allowedPathPrefixes: policy.allowedPathPrefixes ?? DEFAULT_POLICY.allowedPathPrefixes,
	};
}

export function isAllowedPath(file, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	return normalized.allowedPaths.includes(file) || normalized.allowedPathPrefixes.some((prefix) => file.startsWith(prefix));
}

export function shouldScanFile(file, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	if (isAllowedPath(file, normalized)) return false;
	return normalized.sourceExtensions.some((extension) => file.endsWith(extension));
}

export function pathMatchesPattern(file, pattern) {
	if (pattern.startsWith('*.')) return file.endsWith(pattern.slice(1));
	if (pattern.endsWith('/')) return file === pattern.slice(0, -1) || file.startsWith(pattern);
	if (pattern.endsWith('*')) return file.startsWith(pattern.slice(0, -1));
	return file === pattern || file.startsWith(`${pattern}/`);
}

export function scanPathForForbiddenSurface(file, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	if (isAllowedPath(file, normalized)) return [];
	return normalized.forbiddenPaths
		.filter((pattern) => pathMatchesPattern(file, pattern))
		.map((pattern) => ({
			file,
			line: 0,
			column: 0,
			ruleId: 'forbidden-path',
			detail: pattern,
		}));
}

export function isAllowedIPv4(value) {
	return (
		value.startsWith('0.') ||
		value.startsWith('10.') ||
		value.startsWith('127.') ||
		value.startsWith('169.254.') ||
		value.startsWith('192.168.') ||
		/^172\.(1[6-9]|2\d|3[01])\./.test(value) ||
		value.startsWith('192.0.2.') ||
		value.startsWith('198.51.100.') ||
		value.startsWith('203.0.113.') ||
		value.startsWith('1.2.0.192') ||
		value === '255.255.255.255'
	);
}

export function isAllowedEmail(value, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	const domain = value.split('@').pop()?.toLowerCase() ?? '';
	return normalized.allowedEmailDomains.includes(domain) || normalized.allowedEmailDomains.some((allowed) => domain.endsWith(`.${allowed}`));
}

export function isAllowedInternalHostname(value, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	return normalized.allowedInternalHostnames.includes(value.toLowerCase());
}

function clientDomainPattern(domain) {
	const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	return new RegExp(`\\b${escaped}\\b`, 'gi');
}

function finding(file, text, lineIndex, match, ruleId) {
	return {
		file,
		line: lineIndex + 1,
		column: match.index + 1,
		ruleId,
		length: match[0].length,
	};
}

export function scanTextForSensitiveSurface(file, text, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	if (isAllowedPath(file, normalized)) return [];
	const findings = [];
	const lines = text.split(/\r?\n/);

	lines.forEach((line, lineIndex) => {
		for (const rule of RULES) {
			const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
			for (const match of line.matchAll(pattern)) {
				if (rule.id === 'internal-hostname' && isAllowedInternalHostname(match[0], normalized)) continue;
				findings.push(finding(file, line, lineIndex, match, rule.id));
			}
		}

		for (const domain of normalized.forbiddenClientDomains) {
			for (const match of line.matchAll(clientDomainPattern(domain))) {
				findings.push(finding(file, line, lineIndex, match, 'client-domain'));
			}
		}

		for (const match of line.matchAll(PUBLIC_IPV4_PATTERN)) {
			if (!isAllowedIPv4(match[0])) findings.push(finding(file, line, lineIndex, match, 'public-ipv4'));
		}

		for (const match of line.matchAll(EMAIL_PATTERN)) {
			if (!isAllowedEmail(match[0], normalized)) findings.push(finding(file, line, lineIndex, match, 'real-email'));
		}
	});

	return findings;
}

export function scanFileContent(file, text, policy = DEFAULT_POLICY) {
	return [...scanPathForForbiddenSurface(file, policy), ...(shouldScanFile(file, policy) ? scanTextForSensitiveSurface(file, text, policy) : [])];
}

export function scanCommitMessage(text, policy = DEFAULT_POLICY) {
	return scanTextForSensitiveSurface('.git/COMMIT_EDITMSG', text, policy);
}

export function formatFindings(findings) {
	if (findings.length === 0) return 'Repo safety scanner found no sensitive surface.';
	return findings
		.map((finding) => {
			const location = finding.line > 0 ? `${finding.file}:${finding.line}:${finding.column}` : finding.file;
			const detail = finding.detail ? ` (${finding.detail})` : '';
			return `${location} ${finding.ruleId}${detail} [redacted]`;
		})
		.join('\n');
}
