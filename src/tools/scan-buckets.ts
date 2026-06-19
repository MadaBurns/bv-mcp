// SPDX-License-Identifier: BUSL-1.1
/** Cloud-bucket discovery tools — thin fail-soft proxies over bv-recon's bucket-scanner. */
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import { callReconBucketScanStart, callReconBucketScanStatus, callReconBucketFindings, type ReconBinding } from '../lib/recon-binding';

// F7 (OWASP LLM01): upstream bv-recon strings spread into finding metadata below
// are sanitized at the `createFinding` chokepoint (`@blackveil/dns-checks/scoring`,
// recursive string neutralization + length clamp). The former per-tool
// `sanitizeUpstreamObject`/`sanitizeUpstreamValue` opt-ins were removed as redundant
// — every value here flows through `createFinding(... metadata)`.

const CATEGORY = 'bucket_scan' as CheckCategory;

export interface ReconToolOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
	bucketScanKv?: KVNamespace;
}

function unprovisioned(detail: string): CheckResult {
	return buildCheckResult(CATEGORY, [createFinding(CATEGORY, 'Bucket scanning unavailable', 'info', detail, { unprovisioned: true })]) as CheckResult;
}

interface BucketScanScope {
	target?: string;
	providers?: string[];
}

interface BucketScanFindingArgs extends BucketScanScope {
	scanId?: string;
}

interface TargetScopeTokens {
	substring: string[];
	segment: string[];
}

const BUCKET_SCAN_SCOPE_TTL_SECONDS = 24 * 60 * 60;

const PROVIDER_ALIASES: Record<string, string[]> = {
	aws: ['aws', 's3', 'aws_s3', 'amazon_s3'],
	gcp: ['gcp', 'gcp_storage', 'google', 'google_cloud_storage'],
	azure: ['azure', 'azure_blob'],
	alibaba: ['alibaba', 'alibaba_oss'],
	digitalocean: ['digitalocean', 'digitalocean_spaces', 'do_spaces'],
};

const PUBLIC_SUFFIX_LABELS = new Set([
	'com',
	'net',
	'org',
	'edu',
	'gov',
	'mil',
	'int',
	'co',
	'uk',
	'us',
	'ca',
	'au',
	'nz',
	'de',
	'fr',
	'jp',
	'cn',
	'io',
	'ai',
	'app',
	'dev',
	'test',
	'example',
	'invalid',
	'localhost',
	'local',
]);

function scopeKey(scanId: string): string {
	return `bucket-scan-scope:${scanId}`;
}

function normalizeTarget(target: string | undefined): string | undefined {
	if (!target) return undefined;
	let value = target.trim().toLowerCase();
	value = value.replace(/^https?:\/\//, '').split('/')[0] ?? value;
	value = value.replace(/:\d+$/, '').replace(/^\.+|\.+$/g, '');
	return value || undefined;
}

function targetTokens(target: string | undefined): TargetScopeTokens {
	const normalized = normalizeTarget(target);
	if (!normalized) return { substring: [], segment: [] };
	const labels = normalized.split('.').filter(Boolean);
	while (labels[0] === 'www') labels.shift();
	const compact = normalized.replace(/[^a-z0-9]/g, '');
	let strippedSuffix = false;
	while (labels.length > 1 && PUBLIC_SUFFIX_LABELS.has(labels[labels.length - 1]!)) {
		labels.pop();
		strippedSuffix = true;
	}
	if (!strippedSuffix && labels.length > 1) labels.pop();
	const core = labels.join('-');
	const coreCompact = core.replace(/[^a-z0-9]/g, '');
	const substring = new Set<string>();
	const segment = new Set<string>();
	for (const token of [compact, core, coreCompact]) {
		if (token.length >= 3) substring.add(token);
	}
	for (const label of core.split(/[^a-z0-9]+/).filter(Boolean)) {
		if (label.length >= 3) substring.add(label);
		else segment.add(label);
	}
	return { substring: [...substring], segment: [...segment] };
}

function hasTargetScope(tokens: TargetScopeTokens): boolean {
	return tokens.substring.length > 0 || tokens.segment.length > 0;
}

function normalizeProvider(provider: string | undefined): string | undefined {
	if (!provider) return undefined;
	return provider.toLowerCase().trim().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || undefined;
}

function providerAllowed(provider: unknown, requestedProviders: string[] | undefined): boolean {
	if (!requestedProviders?.length) return true;
	if (typeof provider !== 'string') return true;
	const actual = normalizeProvider(provider);
	if (!actual) return true;
	return requestedProviders.some((requested) => {
		const normalized = normalizeProvider(requested);
		if (!normalized) return false;
		const aliases = PROVIDER_ALIASES[normalized] ?? [normalized];
		return aliases.some((alias) => actual === alias || actual.startsWith(`${alias}_`) || alias.startsWith(`${actual}_`));
	});
}

function bucketFindingName(finding: Record<string, unknown>): string {
	for (const key of ['bucketName', 'bucket', 'name', 'containerName']) {
		const value = finding[key];
		if (typeof value === 'string') return value.toLowerCase();
	}
	const endpoint = finding.endpoint;
	return typeof endpoint === 'string' ? endpoint.toLowerCase() : '';
}

function findingInTargetScope(finding: Record<string, unknown>, tokens: TargetScopeTokens): boolean {
	if (!hasTargetScope(tokens)) return true;
	const haystack = `${bucketFindingName(finding)} ${typeof finding.endpoint === 'string' ? finding.endpoint.toLowerCase() : ''}`;
	if (tokens.substring.some((token) => haystack.includes(token))) return true;
	const segments = new Set(haystack.split(/[^a-z0-9]+/).filter(Boolean));
	return tokens.segment.some((token) => segments.has(token));
}

async function rememberBucketScanScope(scanId: string | undefined, scope: BucketScanScope, kv: KVNamespace | undefined): Promise<void> {
	if (!scanId || !kv) return;
	const target = normalizeTarget(scope.target);
	if (!target && !scope.providers?.length) return;
	await kv.put(scopeKey(scanId), JSON.stringify({ target, providers: scope.providers }), { expirationTtl: BUCKET_SCAN_SCOPE_TTL_SECONDS }).catch(() => undefined);
}

async function loadBucketScanScope(scanId: string | undefined, kv: KVNamespace | undefined): Promise<BucketScanScope> {
	if (!scanId || !kv) return {};
	const raw = await kv.get(scopeKey(scanId)).catch(() => null);
	if (!raw) return {};
	try {
		const parsed = JSON.parse(raw) as BucketScanScope;
		return { target: normalizeTarget(parsed.target), providers: Array.isArray(parsed.providers) ? parsed.providers : undefined };
	} catch {
		return {};
	}
}

function filterBucketPayload(payload: Record<string, unknown>, scope: BucketScanScope): Record<string, unknown> {
	const targetScope = targetTokens(scope.target);
	const arrayKey = Array.isArray(payload.data) ? 'data' : Array.isArray(payload.findings) ? 'findings' : undefined;
	if (!arrayKey || (!hasTargetScope(targetScope) && !scope.providers?.length)) return payload;
	const rows = payload[arrayKey] as unknown[];
	const kept: unknown[] = [];
	const filteredSamples: string[] = [];
	for (const row of rows) {
		if (!row || typeof row !== 'object' || Array.isArray(row)) {
			kept.push(row);
			continue;
		}
		const finding = row as Record<string, unknown>;
		if (findingInTargetScope(finding, targetScope) && providerAllowed(finding.provider, scope.providers)) {
			kept.push(row);
			continue;
		}
		if (filteredSamples.length < 5) filteredSamples.push(bucketFindingName(finding) || '(unnamed bucket)');
	}
	const filteredCount = rows.length - kept.length;
	if (filteredCount <= 0) return payload;
	return {
		...payload,
		[arrayKey]: kept,
		count: typeof payload.count === 'number' ? kept.length : payload.count,
		originalCount: typeof payload.count === 'number' ? payload.count : rows.length,
		filteredOutOfScopeCount: filteredCount,
		filteredOutOfScopeSamples: filteredSamples,
		targetScope: scope.target,
		providerScope: scope.providers,
	};
}

export async function scanBucketsStart(args: { target: string; providers?: string[] }, options: ReconToolOptions = {}): Promise<CheckResult> {
	const started = await callReconBucketScanStart(options.reconBinding, options.reconAuthToken, { target: args.target, providers: args.providers });
	if (!started) return unprovisioned(`Bucket discovery is not provisioned in this deployment for ${args.target}.`);
	await rememberBucketScanScope(started.scanId, args, options.bucketScanKv);
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			'Bucket scan started',
			'info',
			`Bucket discovery started for ${args.target} (scanId ${started.scanId}). Poll with scan_buckets_status.`,
			{
				...started,
				scanId: started.scanId,
				status: started.status ?? 'running',
				pollWith: 'scan_buckets_status',
			},
		),
	]) as CheckResult;
}

export async function scanBucketsStatus(args: { scanId: string }, options: ReconToolOptions = {}): Promise<CheckResult> {
	const s = await callReconBucketScanStatus(options.reconBinding, options.reconAuthToken, args.scanId);
	if (!s) return unprovisioned(`Bucket scan status is unavailable for ${args.scanId} (unprovisioned or not found).`);
	const scope = await loadBucketScanScope(args.scanId, options.bucketScanKv);
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Bucket scan ${args.scanId}`, 'info', JSON.stringify(s).slice(0, 800), {
			...s, // F7: opaque upstream payload sanitized at the createFinding chokepoint
			...(scope.target ? { targetScope: scope.target } : {}),
			...(scope.providers?.length ? { providerScope: scope.providers } : {}),
			summary: true,
			scanId: args.scanId, // caller input (already validated) — safe
		}),
	]) as CheckResult;
}

export async function scanBucketsFindings(args: BucketScanFindingArgs, options: ReconToolOptions = {}): Promise<CheckResult> {
	const f = await callReconBucketFindings(options.reconBinding, options.reconAuthToken, args.scanId);
	if (!f) return unprovisioned('Bucket findings are unavailable (unprovisioned or no scan).');
	const rememberedScope = await loadBucketScanScope(args.scanId, options.bucketScanKv);
	const target = normalizeTarget(args.target) ?? rememberedScope.target;
	const providers = args.providers ?? rememberedScope.providers;
	const filtered = filterBucketPayload(f, { target, providers });
	const filteredCount = typeof filtered.filteredOutOfScopeCount === 'number' ? filtered.filteredOutOfScopeCount : 0;
	const detailPrefix = filteredCount > 0 ? `Bucket findings filtered ${filteredCount} out-of-scope upstream candidate(s). ` : '';
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'Bucket findings', 'info', `${detailPrefix}${JSON.stringify(filtered).slice(0, 800)}`, {
			...filtered, // F7: opaque upstream payload sanitized at the createFinding chokepoint
			summary: true,
		}),
	]) as CheckResult;
}
