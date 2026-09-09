import { createHash } from 'node:crypto';

/**
 * @typedef {object} RepoSafetyPolicy
 * @property {string[]} [forbiddenPaths]
 * @property {string[]} [sourceExtensions]
 * @property {string[]} [allowedEmailDomains]
 * @property {string[]} [allowedEmailAddresses]
 * @property {string[]} [allowedDomainSuffixes]
 * @property {string[]} [allowedInternalHostnames]
 * @property {string[]} [forbiddenClientDomains]
 * @property {string[]} [forbiddenClientDomainsSha256]
 * @property {string[]} [forbiddenClientContextPhrasesSha256]
 * @property {string[]} [allowedPaths]
 * @property {string[]} [allowedPathPrefixes]
 */

/** @type {Required<RepoSafetyPolicy>} */
const DEFAULT_POLICY = {
	forbiddenPaths: [],
	sourceExtensions: ['.cjs', '.js', '.json', '.jsonc', '.md', '.mjs', '.py', '.sh', '.sql', '.toml', '.ts', '.tsx', '.yaml', '.yml'],
	allowedEmailDomains: ['example.com', 'example.test', 'example.invalid', 'blackveilsecurity.com'],
	// GitHub's own squash-merge trailers. Callers that scan without policy.json
	// (scanCommitMessage in a commit-msg hook) must allow these too.
	allowedEmailAddresses: ['support@github.com', 'noreply@github.com'],
	allowedDomainSuffixes: ['example.com', 'example.net', 'example.org', 'example.test', 'example.invalid', 'localhost', 'blackveilsecurity.com'],
	allowedInternalHostnames: [],
	forbiddenClientDomains: [],
	forbiddenClientDomainsSha256: [],
	forbiddenClientContextPhrasesSha256: [],
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
	{ id: 'client-context', pattern: /\b(?:sales-meeting verification|production audit|validation batch)\b/gi },
];

// Client-context phrases that must never appear in the repo, stored as SHA-256
// of the lowercased, single-spaced phrase (same hashed-gate mechanism as
// `forbiddenClientDomainsSha256`, so the guard does not itself carry the name).
// Built-in (not policy.json) so the commit-msg hook path, which scans without
// a policy file, still enforces it. Extend per-repo via
// `forbiddenClientContextPhrasesSha256` in policy.json.
export const BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256 = ['ef6b9b94f52b435a826c9558de024878508fb0b151ea98d387c8de54eb03f09a'];
const CLIENT_CONTEXT_PHRASE_MIN_WORDS = 2;
const CLIENT_CONTEXT_PHRASE_MAX_WORDS = 4;
const WORD_TOKEN_PATTERN = /[A-Za-z0-9][A-Za-z0-9-]*/g;

const PUBLIC_IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi;
const ACTIVE_GITHUB_WORKFLOW_PATTERN = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const GITHUB_ACTIONS_THREAT_RULES = [
	{
		id: 'github-actions-megalodon-indicator',
		pattern: /\b(?:build-system@noreply\.dev|ci-bot@automated\.dev|216\.126\.225\.129|Q0I9Imh0dHA6Ly8yMTYu|Megalodon)\b/gi,
	},
	{
		id: 'github-actions-encoded-shell-exec',
		pattern: /\b(?:base64\s+(?:--decode|-d)\b.*\|\s*(?:bash|sh|zsh)\b|python(?:3)?\b.*base64.*\b(?:os\.system|subprocess)\b)/gi,
	},
	{
		id: 'github-actions-remote-shell-exec',
		pattern: /\b(?:(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:env\s+)?(?:bash|sh|zsh)\b|(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b)/gi,
	},
	{
		id: 'github-actions-pull-request-target',
		pattern: /^\s*pull_request_target\s*:/gim,
	},
];
const ALLOWED_GITHUB_ACTIONS_REMOTE_SHELL_INSTALLERS = [];

/** @param {RepoSafetyPolicy} [policy] */
export function normalizePolicy(policy = {}) {
	return {
		...DEFAULT_POLICY,
		...policy,
		forbiddenPaths: policy.forbiddenPaths ?? DEFAULT_POLICY.forbiddenPaths,
		sourceExtensions: policy.sourceExtensions ?? DEFAULT_POLICY.sourceExtensions,
		allowedEmailDomains: policy.allowedEmailDomains ?? DEFAULT_POLICY.allowedEmailDomains,
		allowedEmailAddresses: policy.allowedEmailAddresses ?? DEFAULT_POLICY.allowedEmailAddresses,
		allowedDomainSuffixes: policy.allowedDomainSuffixes ?? DEFAULT_POLICY.allowedDomainSuffixes,
		allowedInternalHostnames: policy.allowedInternalHostnames ?? DEFAULT_POLICY.allowedInternalHostnames,
		forbiddenClientDomains: policy.forbiddenClientDomains ?? DEFAULT_POLICY.forbiddenClientDomains,
		forbiddenClientDomainsSha256: policy.forbiddenClientDomainsSha256 ?? DEFAULT_POLICY.forbiddenClientDomainsSha256,
		forbiddenClientContextPhrasesSha256: policy.forbiddenClientContextPhrasesSha256 ?? DEFAULT_POLICY.forbiddenClientContextPhrasesSha256,
		allowedPaths: policy.allowedPaths ?? DEFAULT_POLICY.allowedPaths,
		allowedPathPrefixes: policy.allowedPathPrefixes ?? DEFAULT_POLICY.allowedPathPrefixes,
	};
}

/** @param {string} file @param {RepoSafetyPolicy} [policy] */
export function isAllowedPath(file, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	return normalized.allowedPaths.includes(file) || normalized.allowedPathPrefixes.some((prefix) => file.startsWith(prefix));
}

/** @param {string} file @param {RepoSafetyPolicy} [policy] */
export function shouldScanFile(file, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	if (isAllowedPath(file, normalized)) return false;
	return normalized.sourceExtensions.some((extension) => file.endsWith(extension));
}

export function pathMatchesPattern(file, pattern) {
	// `*<suffix>` — extension (`*.pdf`) or output-shape (`*-discovery-report.json`) match, any directory.
	if (pattern.startsWith('*')) return file.endsWith(pattern.slice(1));
	if (pattern.endsWith('/')) return file === pattern.slice(0, -1) || file.startsWith(pattern);
	if (pattern.endsWith('*')) return file.startsWith(pattern.slice(0, -1));
	return file === pattern || file.startsWith(`${pattern}/`);
}

/** @param {string} file @param {RepoSafetyPolicy} [policy] */
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

/** @param {string} value @param {RepoSafetyPolicy} [policy] */
export function isAllowedEmail(value, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	const address = value.toLowerCase();
	// Exact-address allowlist. Deliberately narrower than a domain entry: GitHub's
	// generated squash trailers carry `support@github.com` and `*@users.noreply.github.com`,
	// and allowlisting those two DOMAINS would also silence a genuine github.com
	// address pasted into source. Server-side merges bypass local hooks, so these
	// trailers only ever reach the scanner via a push range that merged main —
	// blocking there fails a developer's push for history they did not author.
	if (normalized.allowedEmailAddresses.includes(address)) return true;
	const domain = address.split('@').pop() ?? '';
	if (domain === 'users.noreply.github.com') return true;
	return normalized.allowedEmailDomains.includes(domain) || normalized.allowedEmailDomains.some((allowed) => domain.endsWith(`.${allowed}`));
}

/** @param {string} value @param {RepoSafetyPolicy} [policy] */
export function isAllowedInternalHostname(value, policy = DEFAULT_POLICY) {
	const normalized = normalizePolicy(policy);
	return normalized.allowedInternalHostnames.includes(value.toLowerCase());
}

function clientDomainPattern(domain) {
	const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	return new RegExp(`\\b${escaped}\\b`, 'gi');
}

// Multi-label hostname candidate, e.g. `foo.bar.example.com`. Used to extract
// domain-like tokens from text so each can be checked against the hashed
// forbidden list without storing plaintext names in policy.json.
const DOMAIN_CANDIDATE_PATTERN = /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}\b/gi;

function sha256Hex(value) {
	return createHash('sha256').update(value.toLowerCase()).digest('hex');
}

function* tailSuffixes(domain) {
	const labels = domain.toLowerCase().split('.');
	for (let i = 0; i < labels.length - 1; i++) {
		yield labels.slice(i).join('.');
	}
}

// Sliding word-window candidates (2..4 words, lowercased, single-spaced) so a
// hashed phrase can be matched without the plaintext ever living in the repo.
function* phraseWindows(line) {
	const tokens = [...line.matchAll(WORD_TOKEN_PATTERN)];
	for (let start = 0; start < tokens.length; start++) {
		for (let size = CLIENT_CONTEXT_PHRASE_MIN_WORDS; size <= CLIENT_CONTEXT_PHRASE_MAX_WORDS; size++) {
			const end = start + size;
			if (end > tokens.length) break;
			const first = tokens[start];
			const last = tokens[end - 1];
			const phrase = tokens
				.slice(start, end)
				.map((token) => token[0])
				.join(' ');
			yield { phrase, index: first.index, length: last.index + last[0].length - first.index };
		}
	}
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

export function scanGithubActionsWorkflowForThreats(file, text) {
	if (!ACTIVE_GITHUB_WORKFLOW_PATTERN.test(file)) return [];
	const findings = [];
	const lines = text.split(/\r?\n/);

	lines.forEach((line, lineIndex) => {
		for (const rule of GITHUB_ACTIONS_THREAT_RULES) {
			const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
			for (const match of line.matchAll(pattern)) {
				if (
					rule.id === 'github-actions-remote-shell-exec' &&
					ALLOWED_GITHUB_ACTIONS_REMOTE_SHELL_INSTALLERS.some((installer) => line.includes(installer))
				) {
					continue;
				}
				findings.push(finding(file, line, lineIndex, match, rule.id));
			}
		}
	});

	return findings;
}

/** @param {string} file @param {string} text @param {RepoSafetyPolicy} [policy] */
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

		if (normalized.forbiddenClientDomainsSha256.length > 0) {
			const hashes = new Set(normalized.forbiddenClientDomainsSha256);
			for (const match of line.matchAll(DOMAIN_CANDIDATE_PATTERN)) {
				for (const suffix of tailSuffixes(match[0])) {
					if (hashes.has(sha256Hex(suffix))) {
						findings.push(finding(file, line, lineIndex, match, 'client-domain'));
						break;
					}
				}
			}
		}

		const phraseHashes = new Set([...BUILTIN_CLIENT_CONTEXT_PHRASES_SHA256, ...normalized.forbiddenClientContextPhrasesSha256]);
		for (const window of phraseWindows(line)) {
			if (phraseHashes.has(sha256Hex(window.phrase))) {
				findings.push(finding(file, line, lineIndex, { index: window.index, 0: line.slice(window.index, window.index + window.length) }, 'client-context'));
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

/** @param {string} file @param {string} text @param {RepoSafetyPolicy} [policy] */
export function scanFileContent(file, text, policy = DEFAULT_POLICY) {
	return [
		...scanPathForForbiddenSurface(file, policy),
		...scanGithubActionsWorkflowForThreats(file, text),
		...(shouldScanFile(file, policy) ? scanTextForSensitiveSurface(file, text, policy) : []),
	];
}

/** @param {string} text @param {RepoSafetyPolicy} [policy] */
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
