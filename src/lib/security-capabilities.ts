// SPDX-License-Identifier: BUSL-1.1

/**
 * Security-critical values held by the MCP Worker. Dedicated cross-worker
 * capabilities must never alias another entry in this inventory.
 */
export const MCP_SECURITY_CRITICAL_SECRET_KEYS = [
	'QUOTA_SHARD_SALT',
	'BV_API_KEY',
	'BV_WEB_INTERNAL_KEY',
	'BV_MCP_M365_KEY',
	'BV_MCP_OAUTH_MINT_KEY',
	'BV_MCP_OAUTH_REVOKE_KEY',
	'BV_MCP_TOOL_DELEGATION_KEY',
	'BV_MCP_WATCH_CLEANUP_KEY',
	'BV_MCP_BRAND_WEBHOOK_KEY',
	'BV_MCP_TENANT_KEY',
	'BV_MOBILE_INTERNAL_KEY',
	'BV_INTERNAL_DEV_KEY',
	'BV_INTERNAL_DEV_KEY_2',
	'BV_DOH_TOKEN',
	'BV_CERTSTREAM_ADMIN_KEY',
	'CERTSPOTTER_TOKEN',
	'OAUTH_SIGNING_SECRET',
	'MCP_ACCESS_LOG_IP_ENCRYPTION_KEY',
	'KV_ENVELOPE_KEY',
	'BV_BROWSER_RENDERER_KEY',
	'BV_RECON_KEY',
	'BV_TLS_PROBE_KEY',
	'CF_D1_API_TOKEN',
	'CF_ANALYTICS_TOKEN',
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

/**
 * Detect any global security-secret alias before public auth/tier/JWT handling.
 * A route-local rejection cannot contain an escalation once the holder of one
 * capability already knows the value of an owner, signing, encryption, or
 * other internal authority.
 */
export function securityConfigurationCollision(
	env: Partial<Record<McpSecurityCriticalSecretKey, unknown>>,
): McpSecurityConfigurationCollision | null {
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
