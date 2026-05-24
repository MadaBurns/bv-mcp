// SPDX-License-Identifier: BUSL-1.1

/**
 * App-layer AES-GCM envelope for sensitive KV values (FIND-17).
 *
 * Wire format: `v{keyVersion}:{base64(iv)}:{base64(ct)}`
 * — matches the colon-separated convention used by `encryptIpEvidence` in
 *   `src/mcp/execute.ts` so all app-layer crypto in this codebase shares one
 *   wire-format convention.
 *
 * When `KV_ENVELOPE_KEY` is unset callers should skip these helpers entirely
 * and write/read the raw value as today (backward compat, zero overhead).
 */

// ---------------------------------------------------------------------------
// Internal helpers (mirrors execute.ts — kept local to avoid cross-module dep)
// ---------------------------------------------------------------------------

function base64ToBytes(value: string): Uint8Array {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * AES-GCM encrypt `plaintext` with a random 12-byte IV.
 *
 * Returns a string in the form `v{keyVersion}:{base64(iv)}:{base64(ct)}`.
 * The version tag lets callers detect encrypted values and select the right
 * key for decryption during key-rotation.
 *
 * @param plaintext   UTF-8 string to encrypt.
 * @param keyBytes    Raw 32-byte AES-256 key.
 * @param keyVersion  Monotonically increasing version label (default 1).
 */
export async function sealKv(plaintext: string, keyBytes: Uint8Array, keyVersion = 1): Promise<string> {
	const key = await crypto.subtle.importKey('raw', toArrayBuffer(keyBytes), { name: 'AES-GCM' }, false, ['encrypt']);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encoded = new TextEncoder().encode(plaintext);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(encoded)));
	return `v${keyVersion}:${bytesToBase64(iv)}:${bytesToBase64(ciphertext)}`;
}

/**
 * Decrypt a value produced by `sealKv`. Throws on authentication failure or
 * any other crypto error — callers MUST NOT swallow the throw silently; they
 * should treat it as a signal to fall back to a legacy plaintext read (if
 * migration compatibility is required) rather than trusting corrupted data.
 *
 * @param sealed    String in the form `v{N}:{base64(iv)}:{base64(ct)}`.
 * @param keyBytes  Raw 32-byte AES-256 key matching the one used to seal.
 */
export async function openKv(sealed: string, keyBytes: Uint8Array): Promise<string> {
	const parts = sealed.split(':');
	if (parts.length !== 3) {
		throw new Error('Invalid sealed value: expected v{N}:iv:ct format');
	}
	const [, ivB64, ctB64] = parts;
	const iv = base64ToBytes(ivB64);
	const ciphertext = base64ToBytes(ctB64);
	const key = await crypto.subtle.importKey('raw', toArrayBuffer(keyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
	const plaintext = new Uint8Array(
		await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(ciphertext)),
	);
	return new TextDecoder().decode(plaintext);
}

/**
 * Detect whether `raw` looks like a sealed envelope produced by `sealKv`.
 * Used in migration read-fallback: if the stored value doesn't start with
 * `v{digit}:` it's legacy plaintext and should be parsed as-is.
 */
export function isSealed(raw: string): boolean {
	return /^v\d+:/.test(raw);
}

/**
 * Parse a base64-encoded 32-byte key string (from an env secret binding)
 * into a Uint8Array, or return `null` if the value is absent or malformed.
 * Logs nothing — callers decide whether to surface configuration errors.
 */
export function parseEnvelopeKey(keyBase64: string | undefined): Uint8Array | null {
	if (!keyBase64) return null;
	try {
		const bytes = base64ToBytes(keyBase64);
		return bytes.byteLength === 32 ? bytes : null;
	} catch {
		return null;
	}
}
