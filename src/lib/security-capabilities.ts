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
