// SPDX-License-Identifier: BUSL-1.1

/**
 * Origin signatures for brand-audit watch webhook deliveries to caller-supplied URLs.
 *
 * No per-watch secret is stored. The key is derived on demand:
 *   watchSecret = hex(HMAC-SHA256(WATCH_WEBHOOK_SIGNING_SECRET, LABEL + watchId))
 * and each delivery carries
 *   X-Blackveil-Signature: t=<unix seconds>,v1=hex(HMAC-SHA256(utf8(watchSecret), `${t}.${body}`))
 *
 * `WATCH_WEBHOOK_SIGNING_SECRET` is optional. Unset, empty, short or aliased to
 * another security-critical secret means the feature is off. Neither the server
 * secret, a derived key nor a signature is ever logged here.
 */

import { isStrongDistinctSecurityCapability, type McpSecurityCriticalSecretKey } from './security-capabilities';

/** Header carried on every signed delivery. */
export const WATCH_WEBHOOK_SIGNATURE_HEADER = 'X-Blackveil-Signature';

/** Domain-separation label mixed into the per-watch key derivation. */
export const WATCH_WEBHOOK_KEY_LABEL = 'blackveil:brand-audit-watch-webhook:v1:';

const encoder = new TextEncoder();

function toHex(bytes: ArrayBuffer): string {
	return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256Hex(key: string, message: string): Promise<string> {
	const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	return toHex(await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message)));
}

/** Return the server signing secret only when it passes the repo's strength and distinctness rule. */
export function resolveWatchWebhookSigningSecret(env: Partial<Record<McpSecurityCriticalSecretKey, unknown>>): string | undefined {
	if (!isStrongDistinctSecurityCapability(env, 'WATCH_WEBHOOK_SIGNING_SECRET')) return undefined;
	return env.WATCH_WEBHOOK_SIGNING_SECRET as string;
}

/** Derive the per-watch secret (lowercase hex) handed to the owner at registration. */
export function deriveWatchWebhookSecret(serverSecret: string, watchId: string): Promise<string> {
	return hmacSha256Hex(serverSecret, WATCH_WEBHOOK_KEY_LABEL + watchId);
}

/** Build the `X-Blackveil-Signature` value for the exact body string that is sent. */
export async function signWatchWebhookBody(
	serverSecret: string,
	watchId: string,
	body: string,
	unixSeconds: number = Math.floor(Date.now() / 1000),
): Promise<string> {
	const watchSecret = await deriveWatchWebhookSecret(serverSecret, watchId);
	const signature = await hmacSha256Hex(watchSecret, `${unixSeconds}.${body}`);
	return `t=${unixSeconds},v1=${signature}`;
}
