import { describe, it, expect } from 'vitest';

describe('resolveIssuer host pinning', () => {
	it('returns configured issuer and ignores a spoofed Host', async () => {
		const { resolveIssuer } = await import('../src/oauth/discovery');
		const issuer = resolveIssuer('https://evil.example/.well-known/oauth-authorization-server', 'https://dns-mcp.blackveilsecurity.com');
		expect(issuer).toBe('https://dns-mcp.blackveilsecurity.com');
	});

	it('throws when configured issuer host does not match request host', async () => {
		const { resolveIssuerStrict } = await import('../src/oauth/discovery');
		expect(() => resolveIssuerStrict('https://evil.example/x', 'https://dns-mcp.blackveilsecurity.com')).toThrow(
			'Invalid issuer: request host does not match configured OAUTH_ISSUER',
		);
	});
});
