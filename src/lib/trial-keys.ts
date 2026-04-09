// SPDX-License-Identifier: BUSL-1.1

/**
 * Trial API Key Management
 *
 * Self-contained trial key system stored in the RATE_LIMIT KV namespace
 * under the `trial:` prefix. Keys are crypto-random 64-char hex strings;
 * only their SHA-256 hash is persisted. Trial keys map to an existing
 * tier (default: `developer`) and enforce both time and usage limits.
 *
 * Resolution is integrated into the `resolveTier()` cascade in `tier-auth.ts`:
 * KV tier cache → **trial key lookup** → bv-web service binding → BV_API_KEY.
 */

import type { McpApiKeyTier } from './config';
import { TRIAL_DEFAULT_EXPIRES_DAYS, TRIAL_DEFAULT_MAX_USES, TRIAL_DEFAULT_TIER } from './config';
import { TrialKeyRecordSchema } from '../schemas/auth';
import type { TrialKeyRecord } from '../schemas/auth';

// ---------------------------------------------------------------------------
// Hashing (mirrors tier-auth.ts pattern)
// ---------------------------------------------------------------------------

/** SHA-256 hex digest of a raw token. */
async function hashToken(token: string): Promise<string> {
	const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
	return Array.from(raw)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

// ---------------------------------------------------------------------------
// Key creation
// ---------------------------------------------------------------------------

export interface CreateTrialKeyOptions {
	label: string;
	tier?: McpApiKeyTier;
	expiresInDays?: number;
	maxUses?: number;
}

export interface CreateTrialKeyResult {
	/** Raw API key — display once. */
	rawKey: string;
	/** SHA-256 hex hash — used for KV lookups. */
	hash: string;
	/** The stored record. */
	record: TrialKeyRecord;
}

/**
 * Generate a trial API key and persist it in KV.
 *
 * Returns the raw key (shown once to admin), its hash, and the stored record.
 * The raw key is never stored — only the hash is persisted.
 */
export async function createTrialKey(
	kv: KVNamespace,
	opts: CreateTrialKeyOptions,
): Promise<CreateTrialKeyResult> {
	const tier = opts.tier ?? TRIAL_DEFAULT_TIER;
	const expiresInDays = opts.expiresInDays ?? TRIAL_DEFAULT_EXPIRES_DAYS;
	const maxUses = opts.maxUses ?? TRIAL_DEFAULT_MAX_USES;

	// Generate 32 crypto-random bytes → 64-char hex key
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	const rawKey = Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');

	const hash = await hashToken(rawKey);
	const now = Date.now();
	const expiresAt = now + expiresInDays * 24 * 60 * 60 * 1000;

	const record: TrialKeyRecord = {
		tier,
		expiresAt,
		maxUses,
		currentUses: 0,
		label: opts.label.slice(0, 200),
		createdAt: now,
	};

	// Store with KV expiration TTL matching the trial expiry (auto-cleanup).
	// Add 1 hour buffer so the record is readable slightly past expiry for status checks.
	const ttlSeconds = Math.ceil((expiresAt - now) / 1000) + 3600;
	await kv.put(`trial:${hash}`, JSON.stringify(record), { expirationTtl: ttlSeconds });

	return { rawKey, hash, record };
}

// ---------------------------------------------------------------------------
// Key resolution (called from resolveTier cascade)
// ---------------------------------------------------------------------------

export interface TrialResolution {
	authenticated: true;
	tier: McpApiKeyTier;
	keyHash: string;
	trialInfo: {
		usesRemaining: number;
		expiresAt: number;
		label: string;
	};
}

export interface TrialExpired {
	authenticated: false;
	reason: 'expired' | 'exhausted';
}

/**
 * Look up a trial key by token hash.
 *
 * Returns a `TrialResolution` on success, `TrialExpired` if the key is
 * over its time/usage limit, or `null` if no trial key exists for this hash.
 */
export async function resolveTrialKey(
	kv: KVNamespace,
	tokenHash: string,
): Promise<TrialResolution | TrialExpired | null> {
	let raw: string | null;
	try {
		raw = await kv.get(`trial:${tokenHash}`);
	} catch {
		return null;
	}
	if (!raw) return null;

	let record: TrialKeyRecord;
	try {
		const parsed = JSON.parse(raw);
		const result = TrialKeyRecordSchema.safeParse(parsed);
		if (!result.success) return null;
		record = result.data;
	} catch {
		return null;
	}

	// Check time expiry
	if (Date.now() >= record.expiresAt) {
		return { authenticated: false, reason: 'expired' };
	}

	// Check usage limit
	if (record.currentUses >= record.maxUses) {
		return { authenticated: false, reason: 'exhausted' };
	}

	// Increment usage — read-modify-write (acceptable for trial-volume traffic)
	record.currentUses += 1;
	const remainingTtlMs = record.expiresAt - Date.now();
	const remainingTtlSeconds = Math.max(Math.ceil(remainingTtlMs / 1000) + 3600, 60);
	try {
		await kv.put(`trial:${tokenHash}`, JSON.stringify(record), {
			expirationTtl: remainingTtlSeconds,
		});
	} catch {
		// Non-fatal: usage counter may lag slightly on KV failure
	}

	return {
		authenticated: true,
		tier: record.tier,
		keyHash: tokenHash,
		trialInfo: {
			usesRemaining: record.maxUses - record.currentUses,
			expiresAt: record.expiresAt,
			label: record.label,
		},
	};
}

// ---------------------------------------------------------------------------
// Management helpers
// ---------------------------------------------------------------------------

/** Get the current status of a trial key by its hash. */
export async function getTrialKeyStatus(kv: KVNamespace, hash: string): Promise<TrialKeyRecord | null> {
	try {
		const raw = await kv.get(`trial:${hash}`);
		if (!raw) return null;
		const parsed = JSON.parse(raw);
		const result = TrialKeyRecordSchema.safeParse(parsed);
		return result.success ? result.data : null;
	} catch {
		return null;
	}
}

/** Revoke a trial key by deleting it from KV. Returns true if the key existed. */
export async function revokeTrialKey(kv: KVNamespace, hash: string): Promise<boolean> {
	const existing = await kv.get(`trial:${hash}`);
	if (!existing) return false;
	await kv.delete(`trial:${hash}`);
	return true;
}

/** List trial keys (KV list with `trial:` prefix). Returns hashes and records. */
export async function listTrialKeys(
	kv: KVNamespace,
	opts?: { limit?: number },
): Promise<{ hash: string; record: TrialKeyRecord }[]> {
	const limit = opts?.limit ?? 100;
	const list = await kv.list({ prefix: 'trial:', limit });
	const results: { hash: string; record: TrialKeyRecord }[] = [];

	for (const key of list.keys) {
		const hash = key.name.replace('trial:', '');
		const record = await getTrialKeyStatus(kv, hash);
		if (record) results.push({ hash, record });
	}

	return results;
}
