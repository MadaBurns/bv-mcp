// SPDX-License-Identifier: BUSL-1.1

/**
 * Read a response body without retaining more than `maxBytes` bytes.
 *
 * `Content-Length` is used only as an early-rejection optimization. The stream
 * itself remains authoritative because the header can be absent, compressed,
 * or inaccurate. A body over the cap returns `null`; stream failures propagate
 * so each check can preserve its existing fail-soft behavior.
 */
export async function readResponseTextCapped(response: Response, maxBytes: number): Promise<string | null> {
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
		throw new RangeError('maxBytes must be a non-negative safe integer');
	}

	const declaredRaw = response.headers.get('content-length');
	if (declaredRaw !== null) {
		const declared = Number(declaredRaw);
		if (Number.isFinite(declared) && declared > maxBytes) {
			await response.body?.cancel().catch(() => undefined);
			return null;
		}
	}

	const body = response.body;
	if (!body) return '';

	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let finished = false;

	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) {
				finished = true;
				break;
			}
			if (!value) continue;
			if (value.byteLength > maxBytes - total) return null;
			chunks.push(value);
			total += value.byteLength;
		}
	} finally {
		if (!finished) {
			await reader.cancel('response body exceeded byte limit').catch(() => undefined);
		}
		reader.releaseLock();
	}

	if (total === 0) return '';
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(bytes);
}
