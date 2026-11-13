// SPDX-License-Identifier: BUSL-1.1

/**
 * Security-critical values held by the MCP Worker. Dedicated cross-worker
 * capabilities must never alias another entry in this inventory.
 */
export const MCP_SECURITY_CRITICAL_SECRET_KEYS = [
	'QUOTA_SHARD_SALT',
	'BV_API_KEY',
	'BV_ROAMING_OWNER_KEY',
	'BV_WEB_INTERNAL_KEY',
	'BV_MCP_M365_KEY',
	'BV_MCP_OAUTH_MINT_KEY',
	'BV_MCP_OAUTH_REVOKE_KEY',
	'BV_MCP_EMA_ADMIN_KEY',
	'BV_MCP_TOOL_DELEGATION_KEY',
	'BV_MCP_WATCH_CLEANUP_KEY',
	'BV_MCP_BRAND_WEBHOOK_KEY',
	// OPTIONAL: unset = brand-audit watch webhook deliveries stay unsigned.
	'WATCH_WEBHOOK_SIGNING_SECRET',
	'BV_MCP_TENANT_KEY',
	'BV_MOBILE_INTERNAL_KEY',
	'BV_INTERNAL_DEV_KEY',
	'BV_INTERNAL_DEV_KEY_2',
	'BV_LOAD_TEST_KEY',
	'BV_DOH_TOKEN',
	'BV_CERTSTREAM_ADMIN_KEY',
	'CERTSPOTTER_TOKEN',
	'TYPESAFE_AI_API_KEY',
	'OAUTH_SIGNING_SECRET',
	// Optional rotation-window secret (verify only). Never required for deploy; see PRODUCTION_REQUIRED_SECRETS.
	'OAUTH_SIGNING_SECRET_PREVIOUS',
	'MCP_ACCESS_LOG_IP_ENCRYPTION_KEY',
	'KV_ENVELOPE_KEY',
	'BV_BROWSER_RENDERER_KEY',
	'BV_RECON_KEY',
	'BV_TLS_PROBE_KEY',
	'CF_D1_API_TOKEN',
	'CF_ANALYTICS_TOKEN',
	'ALERT_WEBHOOK_URL',
] as const;

export type McpSecurityCriticalSecretKey = (typeof MCP_SECURITY_CRITICAL_SECRET_KEYS)[number];

/** Cross-worker/internal capabilities are generated with at least 256 bits. */
export const MIN_SECURITY_CAPABILITY_BYTES = 32;

/** Return only a peer's name; secret values must never enter logs or errors. */
export function securityCapabilityCollision(
	env: Partial<Record<McpSecurityCriticalSecretKey, unknown>>,
	capabilityKey: McpSecurityCriticalSecretKey,
): McpSecurityCriticalSecretKey | null {
	const value = env[capabilityKey];
	if (typeof value !== 'string' || value.length === 0) return null;
	for (const peerKey of MCP_SECURITY_CRITICAL_SECRET_KEYS) {
		if (peerKey === capabilityKey) continue;
		const peer = env[peerKey];
		if (typeof peer === 'string' && peer.length > 0 && peer === value) return peerKey;
	}
	return null;
}

/** Require a strong, non-aliased dedicated capability from the shared SSOT. */
export function isStrongDistinctSecurityCapability(
	env: Partial<Record<McpSecurityCriticalSecretKey, unknown>>,
	capabilityKey: McpSecurityCriticalSecretKey,
): boolean {
	const candidate = env[capabilityKey];
	return (
		typeof candidate === 'string' &&
		new TextEncoder().encode(candidate).byteLength >= MIN_SECURITY_CAPABILITY_BYTES &&
		securityCapabilityCollision(env, capabilityKey) === null
	);
}

export interface McpSecurityConfigurationCollision {
	left: McpSecurityCriticalSecretKey;
	right: McpSecurityCriticalSecretKey;
}

function withoutRedundantPreviousSigningSecret(
	env: Partial<Record<McpSecurityCriticalSecretKey, unknown>>,
): Partial<Record<McpSecurityCriticalSecretKey, unknown>> {
	const previous = env.OAUTH_SIGNING_SECRET_PREVIOUS;
	// Copy the env only in the rare equal case; the common (unset) path stays allocation-free.
	return typeof previous === 'string' && previous === env.OAUTH_SIGNING_SECRET ? { ...env, OAUTH_SIGNING_SECRET_PREVIOUS: undefined } : env;
}

/**
 * Detect any global security-secret alias before public auth/tier/JWT handling.
 * A route-local rejection cannot contain an escalation once the holder of one
 * capability already knows the value of an owner, signing, encryption, or
 * other internal authority.
 *
 * One alias is tolerated: OAUTH_SIGNING_SECRET_PREVIOUS equal to OAUTH_SIGNING_SECRET is the same
 * authority named twice (a half-finished rotation), not an escalation. The JWT verifier ignores it
 * with a one-time warning, so it must not turn into a Worker-wide 503. Equality with any OTHER
 * inventory entry still collides.
 */
export function securityConfigurationCollision(
	rawEnv: Partial<Record<McpSecurityCriticalSecretKey, unknown>>,
): McpSecurityConfigurationCollision | null {
	const env = withoutRedundantPreviousSigningSecret(rawEnv);
	for (let leftIndex = 0; leftIndex < MCP_SECURITY_CRITICAL_SECRET_KEYS.length; leftIndex += 1) {
		const left = MCP_SECURITY_CRITICAL_SECRET_KEYS[leftIndex];
		const leftValue = env[left];
		if (typeof leftValue !== 'string' || leftValue.length === 0) continue;
		for (let rightIndex = leftIndex + 1; rightIndex < MCP_SECURITY_CRITICAL_SECRET_KEYS.length; rightIndex += 1) {
			const right = MCP_SECURITY_CRITICAL_SECRET_KEYS[rightIndex];
			const rightValue = env[right];
			if (typeof rightValue === 'string' && rightValue.length > 0 && rightValue === leftValue) {
				return { left, right };
			}
		}
	}
	return null;
}
