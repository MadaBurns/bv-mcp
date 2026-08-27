// SPDX-License-Identifier: BUSL-1.1

/**
 * Canonical tenant principal shared by every trusted authentication front door.
 *
 * OAuth access tokens carry the tenant id in their verified `sub` claim, while
 * bv-web service-binding calls carry the same tenant id in a trusted X-Tenant
 * header. Both must land in one quota/ownership namespace. Domain separation
 * from credential hashes prevents an attacker-controlled API key from aliasing
 * a tenant principal even if its plaintext resembles an issuer/subject tuple.
 */

const SAFE_TENANT_SUBJECT = /^[A-Za-z0-9:_-]{1,128}$/;

export function normalizePrincipalIssuer(rawIssuer: string): string {
	const url = new URL(rawIssuer);
	if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
		throw new Error('Invalid canonical principal issuer');
	}
	const pathname = url.pathname.replace(/\/+$/, '');
	return `${url.origin}${pathname}`;
}

export type OAuthPrincipalKind = 'tenant' | 'owner';

export async function deriveCanonicalOAuthPrincipal(
	issuer: string,
	subject: string,
	kind: OAuthPrincipalKind,
): Promise<string> {
	if (!SAFE_TENANT_SUBJECT.test(subject)) {
		throw new Error('Invalid canonical OAuth subject');
	}
	const canonicalIssuer = normalizePrincipalIssuer(issuer);
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`oauth-${kind}\0${canonicalIssuer}\0${subject}`)),
	);
	return Array.from(digest)
		.map((byte) => byte.toString(16).padStart(2, '0'))
		.join('');
}

export function deriveCanonicalTenantPrincipal(issuer: string, tenantSubject: string): Promise<string> {
	return deriveCanonicalOAuthPrincipal(issuer, tenantSubject, 'tenant');
}
