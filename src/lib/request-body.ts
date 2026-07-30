// SPDX-License-Identifier: BUSL-1.1

export type BoundedTextResult = { ok: true; text: string; byteLength: number } | { ok: false; byteLength: number };

/** Read a request body without ever buffering more than maxBytes. */
export async function readBoundedText(request: Request, maxBytes: number): Promise<BoundedTextResult> {
	const contentLength = request.headers.get('content-length');
	if (contentLength) {
		const declared = Number(contentLength);
		if (Number.isFinite(declared) && declared > maxBytes) return { ok: false, byteLength: declared };
	}

	const reader = request.body?.getReader();
	if (!reader) return { ok: true, text: '', byteLength: 0 };

	let total = 0;
	let text = '';
	const decoder = new TextDecoder();
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel().catch(() => undefined);
				return { ok: false, byteLength: total };
			}
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
		return { ok: true, text, byteLength: total };
	} finally {
		reader.releaseLock();
	}
}
