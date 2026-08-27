// SPDX-License-Identifier: BUSL-1.1

import { deriveCanonicalOAuthPrincipal } from './auth-principal';
import type { OAuthPrincipalKind } from './auth-principal';
import type { TierAuthResult } from './tier-auth';
import { resolveIssuerStrict } from '../oauth/discovery';
import { constantTimeEqual, verifyJwtOwnershipProof } from '../oauth/jwt';

/** Public header carrying one retained historical OAuth access token. */
export const LEGACY_BRAND_OWNER_PROOF_HEADER = 'x-bv-legacy-owner-token';

/** Retired OAuth access tokens had a maximum lifetime of 90 days. */
const LEGACY_OAUTH_JWT_MAX_LIFETIME_SECONDS = 90 * 24 * 60 * 60;
/** Bound parsing and hashing work before touching the historical JWT. */
const LEGACY_OWNER_PROOF_MAX_TOKEN_CHARS = 8 * 1024;
const CANONICAL_OWNER_ID = /^[0-9a-f]{64}$/;

export type LegacyBrandOwnerProofResult = { status: 'absent' } | { status: 'invalid' } | { status: 'valid'; legacyOwnerId: string };

function principalKindForTier(tier: unknown): OAuthPrincipalKind | null {
	if (tier === 'owner') return 'owner';
	if (tier === 'developer' || tier === 'enterprise') return 'tenant';
	return null;
}

function parseProofBearer(rawHeader: string | undefined): string | null | undefined {
	if (rawHeader === undefined) return undefined;
	if (!rawHeader.startsWith('Bearer ')) return null;
	const token = rawHeader.slice(7).trim();
	if (!token || token.length > LEGACY_OWNER_PROOF_MAX_TOKEN_CHARS || token.split('.').length !== 3) return null;
	return token;
}

async function sha256Bytes(value: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

function hex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');
}

/**
 * Resolve one historical raw-JWT owner hash without treating the historical
 * token as authentication.
 *
 * The request must already have a valid current OAuth identity. The historical
 * JWT must still verify under the pinned issuer/signing key, and its
 * issuer+subject+principal-kind digest must equal the current canonical owner
 * in constant time. A static key, another tenant, an owner/tenant namespace
 * change, or a forged token therefore cannot claim legacy rows.
 */
export async function resolveLegacyBrandOwnerProof(
	rawHeader: string | undefined,
	currentAuth: TierAuthResult,
	env: { OAUTH_SIGNING_SECRET?: string; OAUTH_ISSUER?: string },
	requestUrl: string,
): Promise<LegacyBrandOwnerProofResult> {
	const token = parseProofBearer(rawHeader);
	if (token === undefined) return { status: 'absent' };
	if (
		token === null ||
		!currentAuth.authenticated ||
		!currentAuth.keyHash ||
		!CANONICAL_OWNER_ID.test(currentAuth.keyHash) ||
		!currentAuth.oauthPrincipalKind ||
		!env.OAUTH_SIGNING_SECRET
	) {
		return { status: 'invalid' };
	}

	try {
		const issuer = resolveIssuerStrict(requestUrl, env.OAUTH_ISSUER);
		const claims = await verifyJwtOwnershipProof(token, {
			secret: env.OAUTH_SIGNING_SECRET,
			issuer,
			audience: `${issuer}/mcp`,
			maxLifetimeSeconds: LEGACY_OAUTH_JWT_MAX_LIFETIME_SECONDS,
		});
		const historicalKind = principalKindForTier(claims.tier);
		if (historicalKind === null || historicalKind !== currentAuth.oauthPrincipalKind) return { status: 'invalid' };

		const historicalCanonicalOwner = await deriveCanonicalOAuthPrincipal(issuer, claims.sub, historicalKind);
		const currentOwnerBytes = Uint8Array.from(currentAuth.keyHash.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
		const historicalOwnerBytes = Uint8Array.from(historicalCanonicalOwner.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
		if (currentOwnerBytes.byteLength !== 32 || !constantTimeEqual(currentOwnerBytes, historicalOwnerBytes)) {
			return { status: 'invalid' };
		}

		return { status: 'valid', legacyOwnerId: hex(await sha256Bytes(token)).slice(0, 16) };
	} catch {
		return { status: 'invalid' };
	}
}
