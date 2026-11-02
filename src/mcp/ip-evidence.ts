// SPDX-License-Identifier: BUSL-1.1

/** IP-evidence AES-GCM helpers, split out of execute.ts (no behaviour change). */

import { logError } from '../lib/log';

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

// Module-scoped cache so a mis-configured key logs once, then skips silently
// instead of throwing on every request. Map key = the base64 env value, so a
// later config fix (rotated key) gets re-evaluated automatically.
const encryptionKeyValidationCache = new Map<string, { valid: boolean }>();

function validateEncryptionKeyOnce(keyBase64: string): boolean {
	const cached = encryptionKeyValidationCache.get(keyBase64);
	if (cached) return cached.valid;
	let valid = false;
	try {
		valid = base64ToBytes(keyBase64).byteLength === 32;
	} catch {
		valid = false;
	}
	encryptionKeyValidationCache.set(keyBase64, { valid });
	if (!valid) {
		// Surface once at error level — operators need to see this in alerting.
		// Subsequent requests hit the cache and skip without re-logging.
		logError(
			'Invalid MCP_ACCESS_LOG_IP_ENCRYPTION_KEY: must be 32 bytes (base64-decoded). Access-log IP ciphertext disabled until fixed.',
			{
				category: 'config',
				details: {
					keyBytes: (() => {
						try {
							return base64ToBytes(keyBase64).byteLength;
						} catch {
							return 'unparseable_base64';
						}
					})(),
				},
			},
		);
	}
	return valid;
}

export async function encryptIpEvidence(ip: string, keyBase64: string | undefined): Promise<string | null> {
	if (!keyBase64 || ip === 'unknown') return null;
	if (!validateEncryptionKeyOnce(keyBase64)) return null;
	const rawKey = base64ToBytes(keyBase64);
	const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), { name: 'AES-GCM' }, false, ['encrypt']);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const plaintext = new TextEncoder().encode(ip);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)));
	return `v1:${bytesToBase64(iv)}:${bytesToBase64(ciphertext)}`;
}

/**
 * Inverse of {@link encryptIpEvidence}: parses the `v1:iv:ct` wire format and
 * AES-GCM-decrypts the raw IP. Returns `null` on any failure (missing key,
 * malformed wire, wrong key length, decrypt error) — callers fall back to the
 * masked IP. Operator-only re-identification surface (forensics endpoint).
 */
export async function decryptIpEvidence(wire: string, keyBase64: string | undefined): Promise<string | null> {
	if (!keyBase64 || !wire) return null;
	const parts = wire.split(':');
	if (parts.length !== 3) return null; // expected v1:iv:ct
	try {
		const rawKey = base64ToBytes(keyBase64);
		if (rawKey.byteLength !== 32) return null;
		const iv = base64ToBytes(parts[1]);
		const ct = base64ToBytes(parts[2]);
		const key = await crypto.subtle.importKey('raw', toArrayBuffer(rawKey), { name: 'AES-GCM' }, false, ['decrypt']);
		const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(ct));
		return new TextDecoder().decode(pt);
	} catch {
		return null;
	}
}
