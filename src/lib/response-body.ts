// SPDX-License-Identifier: BUSL-1.1

export async function disposeUnreadResponseBody(response: Response): Promise<void> {
	if (!response.body) return;
	try {
		await response.body.cancel();
	} catch {
		// The body may already be locked or consumed.
	}
}

/**
 * Bounded streaming body readers.
 *
 * Both read at most `maxBytes` BYTES from a response body stream, then cancel
 * the reader (always, in a `finally`). The bound is on the cumulative BYTE
 * length of the chunks read (`Uint8Array.byteLength`) — NOT the decoded string
 * length, which on multi-byte UTF-8 can be ~3-4x smaller than the byte count
 * and would let an attacker-controlled endpoint buffer far more than intended.
 *
 * Fail-open: never throw. The body stream the caller passes is the only thing
 * consumed — the caller owns `response.clone()` if it needs the original
 * undisturbed.
 */

/** Drain the stream up to a byte cap. Returns the accumulated chunks, the
 * cumulative byte total read, and whether the cap was reached/exceeded. */
async function drainBounded(
	body: ReadableStream<Uint8Array> | null,
	maxBytes: number,
): Promise<{ chunks: Uint8Array[]; total: number; overflowed: boolean }> {
	const chunks: Uint8Array[] = [];
	let total = 0;
	let overflowed = false;
	if (!body) return { chunks, total, overflowed };
	const reader = body.getReader();
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value) continue;
			const remaining = Math.max(maxBytes - total, 0);
			if (value.byteLength > remaining) {
				if (remaining > 0) {
					chunks.push(value.slice(0, remaining));
					total += remaining;
				}
				overflowed = true;
				break;
			}
			chunks.push(value);
			total += value.byteLength;
		}
	} finally {
		// Always release the underlying stream — best-effort, swallow errors.
		try {
			await reader.cancel();
		} catch {
			/* fail-open */
		}
	}
	return { chunks, total, overflowed };
}

/** Concatenate chunks into one Uint8Array. */
function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
	const out = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.byteLength;
	}
	return out;
}

/**
 * Read at most `maxBytes` bytes from a body stream, then cancel it. Byte-accurate
 * (bounds on cumulative `Uint8Array.byteLength`, truncating the body once the cap
 * is reached). Fail-open: returns '' on any error or a null/empty body. Caller
 * owns cloning the response if it needs the original undisturbed.
 */
export async function readBoundedText(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string> {
	try {
		const { chunks, total } = await drainBounded(body, maxBytes);
		if (total === 0) return '';
		return new TextDecoder().decode(concatChunks(chunks, total));
	} catch {
		return '';
	}
}

/**
 * Like {@link readBoundedText} but NULL-on-overflow: returns `null` when the body
 * exceeds `maxBytes` (rather than truncating), and `null` on any error or a null
 * body. Used where the caller must treat an over-cap body as "unverifiable"
 * rather than processing a partial prefix (e.g. capability-document integrity).
 */
export async function readBoundedOrNull(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string | null> {
	try {
		if (!body) return null;
		const { chunks, total, overflowed } = await drainBounded(body, maxBytes);
		if (overflowed) return null;
		return new TextDecoder().decode(concatChunks(chunks, total));
	} catch {
		return null;
	}
}
