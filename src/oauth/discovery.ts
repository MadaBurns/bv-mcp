// SPDX-License-Identifier: BUSL-1.1
import {
	OAUTH_CODE_CHALLENGE_METHODS_SUPPORTED,
	OAUTH_GRANT_TYPES_SUPPORTED,
	OAUTH_RESPONSE_TYPES_SUPPORTED,
	OAUTH_SCOPES_SUPPORTED,
	OAUTH_TOKEN_AUTH_METHODS_SUPPORTED,
} from '../lib/config';

/**
 * Resolve the canonical OAuth issuer URL. When `envIssuer` is provided it wins (trailing
 * slash stripped); otherwise the issuer is derived from the request URL's origin. Deriving
 * from the request means the `Host` header influences the advertised `authorization_endpoint`
 * and `token_endpoint` in discovery metadata — in production, always set `OAUTH_ISSUER` to
 * prevent Host-header spoofing from injecting attacker-controlled endpoint URLs. Cloudflare's
 * route binding normally constrains Host, but setting `OAUTH_ISSUER` is the hardening path.
 */
export function resolveIssuer(requestUrl: string, envIssuer?: string): string {
	if (envIssuer && envIssuer.length > 0) return envIssuer.replace(/\/$/, '');
	const url = new URL(requestUrl);
	return `${url.protocol}//${url.host}`;
}

/** Build RFC 8414 OAuth 2.0 Authorization Server Metadata for the given issuer. */
export function buildAuthorizationServerMetadata(issuer: string): Record<string, unknown> {
	return {
		issuer,
		authorization_endpoint: `${issuer}/oauth/authorize`,
		token_endpoint: `${issuer}/oauth/token`,
		registration_endpoint: `${issuer}/oauth/register`,
		scopes_supported: [...OAUTH_SCOPES_SUPPORTED],
		response_types_supported: [...OAUTH_RESPONSE_TYPES_SUPPORTED],
		grant_types_supported: [...OAUTH_GRANT_TYPES_SUPPORTED],
		token_endpoint_auth_methods_supported: [...OAUTH_TOKEN_AUTH_METHODS_SUPPORTED],
		code_challenge_methods_supported: [...OAUTH_CODE_CHALLENGE_METHODS_SUPPORTED],
		service_documentation: 'https://github.com/MadaBurns/bv-mcp',
	};
}

/** Build RFC 9728 OAuth 2.0 Protected Resource Metadata pointing at the `/mcp` resource. */
export function buildProtectedResourceMetadata(issuer: string): Record<string, unknown> {
	return {
		resource: `${issuer}/mcp`,
		authorization_servers: [issuer],
		scopes_supported: [...OAUTH_SCOPES_SUPPORTED],
		bearer_methods_supported: ['header'],
	};
}
