// SPDX-License-Identifier: BUSL-1.1
import {
	OAUTH_CODE_CHALLENGE_METHODS_SUPPORTED,
	OAUTH_GRANT_TYPES_SUPPORTED,
	OAUTH_RESPONSE_TYPES_SUPPORTED,
	OAUTH_SCOPES_SUPPORTED,
	OAUTH_TOKEN_AUTH_METHODS_SUPPORTED,
} from '../lib/config';

export function resolveIssuer(requestUrl: string, envIssuer?: string): string {
	if (envIssuer && envIssuer.length > 0) return envIssuer.replace(/\/$/, '');
	const u = new URL(requestUrl);
	return `${u.protocol}//${u.host}`;
}

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

export function buildProtectedResourceMetadata(issuer: string): Record<string, unknown> {
	return {
		resource: `${issuer}/mcp`,
		authorization_servers: [issuer],
		scopes_supported: [...OAUTH_SCOPES_SUPPORTED],
		bearer_methods_supported: ['header'],
	};
}
