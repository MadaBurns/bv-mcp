// SPDX-License-Identifier: BUSL-1.1

/**
 * KV-backed sliding-window counter for fuzzing-detection events.
 *
 * Key shape: `fuzz:p:<principalId>:e:<bucketEpoch10s>:<kind>` → integer count.
 * Each write coalesces into the 10-second bucket (`floor(epochSec / 10) * 10`)
 * to keep KV op counts bounded under high-volume bursts. CF KV is eventually
 * consistent — two parallel writes to the same key may lose one increment;
 * acceptable for fuzzing detection where exact counts don't matter, only
 * that the magnitude trips the threshold.
 *
 * TTL is the window length, clamped to KV's 60s minimum.
 */

import type { FuzzKind, FuzzEvent } from './fuzzing-detector';

const BUCKET_SECONDS = 10;
const KEY_PREFIX = 'fuzz:p:';

function bucketEpoch(epochSec: number): number {
	return Math.floor(epochSec / BUCKET_SECONDS) * BUCKET_SECONDS;
}

function keyFor(principalId: string, bucket: number, kind: FuzzKind): string {
	return `${KEY_PREFIX}${principalId}:e:${bucket}:${kind}`;
}

function principalPrefix(principalId: string): string {
	return `${KEY_PREFIX}${principalId}:e:`;
}

/**
 * Increment the counter for the given principal+kind in the current 10s bucket.
 * Errors are swallowed — fuzzing detection must never break the request path.
 */
export async function recordEvent(kv: KVNamespace, principalId: string, kind: FuzzKind, epochSec: number): Promise<void> {
	try {
		const bucket = bucketEpoch(epochSec);
		const key = keyFor(principalId, bucket, kind);
		const current = await kv.get(key);
		const next = current === null ? 1 : Number.parseInt(current, 10) + 1;
		// TTL of 600s (10 min) is far more than any realistic windowSeconds default and
		// gives KV slack to evict; readers filter by epoch so stale entries are inert.
		await kv.put(key, String(next), { expirationTtl: 600 });
	} catch {
		// Swallow — see chaos test "KV down".
	}
}

/**
 * Read events for `principalId` whose bucket falls within `[nowSec - windowSeconds, nowSec]`.
 * Coalesced counts are expanded into one FuzzEvent per increment so the detector can
 * score uniformly without knowing about bucket aggregation.
 */
export async function readWindow(kv: KVNamespace, principalId: string, nowSec: number, windowSeconds: number): Promise<FuzzEvent[]> {
	try {
		const list = await kv.list({ prefix: principalPrefix(principalId) });
		const cutoff = nowSec - windowSeconds;
		const events: FuzzEvent[] = [];
		for (const k of list.keys) {
			// Key shape: fuzz:p:<principalId>:e:<bucket>:<kind>
			const tail = k.name.slice(principalPrefix(principalId).length); // `<bucket>:<kind>`
			const idx = tail.indexOf(':');
			if (idx < 0) continue;
			const bucket = Number.parseInt(tail.slice(0, idx), 10);
			const kind = tail.slice(idx + 1) as FuzzKind;
			if (Number.isNaN(bucket) || bucket < cutoff) continue;
			const raw = await kv.get(k.name);
			const count = raw === null ? 0 : Number.parseInt(raw, 10);
			for (let i = 0; i < count; i++) {
				events.push({ kind, epochSec: bucket });
			}
		}
		return events;
	} catch {
		return [];
	}
}
