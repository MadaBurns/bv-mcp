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
 * Both read at most `maxBytes` BYTES from a response body stream, cancel any
 * unread remainder, and release the reader lock. The bound is on the cumulative BYTE
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
): Promise<{ chunks: Uint8Array[]; total: number; consumed: number; overflowed: boolean; errored: boolean }> {
	const chunks: Uint8Array[] = [];
	let total = 0;
	let consumed = 0;
	let overflowed = false;
	let errored = false;
	if (!body) return { chunks, total, consumed, overflowed, errored };
	let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
	let finished = false;
	try {
		reader = body.getReader();
		for (;;) {
			const { done, value } = await reader.read();
			if (done) {
				finished = true;
				break;
			}
			if (!value) continue;
			consumed += value.byteLength;
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
	} catch {
		errored = true;
	} finally {
		if (reader && !finished) {
			try {
				await reader.cancel();
			} catch {
				/* fail-open */
			}
		}
		try {
			reader?.releaseLock();
		} catch {
			// A hostile/locked stream must not escape this fail-open reader.
		}
	}
	return { chunks, total, consumed, overflowed, errored };
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
 * Read at most `maxBytes` bytes from a body stream, cancelling any unread remainder. Byte-accurate
 * (bounds on cumulative `Uint8Array.byteLength`, truncating the body once the cap
 * is reached). Fail-open: returns '' on any error or a null/empty body. Caller
 * owns cloning the response if it needs the original undisturbed.
 */
export async function readBoundedText(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string> {
	try {
		const { chunks, total, errored } = await drainBounded(body, maxBytes);
		if (errored) return '';
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
		const { chunks, total, overflowed, errored } = await drainBounded(body, maxBytes);
		if (overflowed || errored) return null;
		return new TextDecoder().decode(concatChunks(chunks, total));
	} catch {
		return null;
	}
}

/**
 * Parse a JSON response without buffering more than `maxBytes`. Returns `null`
 * for malformed, unreadable, or oversized bodies. `Content-Length` is only an
 * early-rejection hint; the decoded stream remains authoritative.
 */
export async function readJsonResponseCapped<T>(response: Response, maxBytes: number): Promise<T | null> {
	// A standards-compliant fetch/service-binding Response always exposes a
	// `body` property (stream or null). A few focused unit tests use minimal
	// object doubles with only `.json()`; preserve those non-runtime seams while
	// keeping every real network response on the bounded streaming path.
	if ((response as Response & { body?: ReadableStream<Uint8Array> | null }).body === undefined) {
		try {
			return (await response.json()) as T;
		} catch {
			return null;
		}
	}
	const declared = Number(response.headers.get('content-length'));
	if (Number.isFinite(declared) && declared > maxBytes) {
		await disposeUnreadResponseBody(response);
		return null;
	}
	const raw = await readBoundedOrNull(response.body, maxBytes);
	if (raw === null) return null;
	try {
		return JSON.parse(raw) as T;
	} catch {
		return null;
	}
}

/** Read an entire response as text only when it fits inside `maxBytes`. */
export async function readTextResponseCapped(response: Response, maxBytes: number): Promise<string | null> {
	const declared = Number(response.headers.get('content-length'));
	if (Number.isFinite(declared) && declared > maxBytes) {
		await disposeUnreadResponseBody(response);
		return null;
	}
	return readBoundedOrNull(response.body, maxBytes);
}

/**
 * Metadata-preserving variant for callers with an aggregate cross-response
 * budget. `bytesRead` is the actual retained/read byte count on streamed paths;
 * a Content-Length early rejection conservatively charges `maxBytes` even
 * though the body is cancelled before it is read.
 */
export async function readTextResponseCappedDetailed(
	response: Response,
	maxBytes: number,
): Promise<{ text: string | null; bytesRead: number; overflowed: boolean; errored: boolean }> {
	const declared = Number(response.headers.get('content-length'));
	if (Number.isFinite(declared) && declared > maxBytes) {
		await disposeUnreadResponseBody(response);
		return { text: null, bytesRead: maxBytes, overflowed: true, errored: false };
	}
	if (!response.body) return { text: null, bytesRead: 0, overflowed: false, errored: false };
	const { chunks, total, consumed, overflowed, errored } = await drainBounded(response.body, maxBytes);
	return {
		text: overflowed || errored ? null : new TextDecoder().decode(concatChunks(chunks, total)),
		bytesRead: consumed,
		overflowed,
		errored,
	};
}
