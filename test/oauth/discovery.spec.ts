import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { resolveIssuer } from '../../src/oauth/discovery';

describe('oauth discovery endpoints', () => {
	it('GET /.well-known/oauth-authorization-server returns RFC 8414 metadata', async () => {
		const res = await SELF.fetch('https://example.com/.well-known/oauth-authorization-server');
		expect(res.status).toBe(200);
		const meta = (await res.json()) as Record<string, unknown>;
		expect(meta.issuer).toBeTypeOf('string');
		expect(meta.authorization_endpoint).toMatch(/\/oauth\/authorize$/);
		expect(meta.token_endpoint).toMatch(/\/oauth\/token$/);
		expect(meta.registration_endpoint).toMatch(/\/oauth\/register$/);
		expect(meta.code_challenge_methods_supported).toEqual(['S256']);
		expect(meta.response_types_supported).toContain('code');
		expect(meta.grant_types_supported).toContain('authorization_code');
	});

	it('GET /.well-known/oauth-protected-resource returns RFC 9728 metadata', async () => {
		const res = await SELF.fetch('https://example.com/.well-known/oauth-protected-resource');
		expect(res.status).toBe(200);
		const meta = (await res.json()) as Record<string, unknown>;
		expect(meta.resource).toBeTypeOf('string');
		expect(Array.isArray(meta.authorization_servers)).toBe(true);
	});

	it('path-suffixed variant is also served', async () => {
		const res = await SELF.fetch('https://example.com/.well-known/oauth-protected-resource/mcp');
		expect(res.status).toBe(200);
	});
});

describe('resolveIssuer', () => {
	it('envIssuer wins over request URL', () => {
		expect(resolveIssuer('https://request.example.com/path', 'https://configured.example.com')).toBe(
			'https://configured.example.com',
		);
	});

	it('strips trailing slash from envIssuer', () => {
		expect(resolveIssuer('https://req.test/', 'https://issuer.test/')).toBe('https://issuer.test');
	});

	it('treats empty-string envIssuer as unset and falls back to request origin', () => {
		expect(resolveIssuer('https://req.test/whatever', '')).toBe('https://req.test');
	});

	it('falls back to request origin (preserving port) when envIssuer is undefined', () => {
		expect(resolveIssuer('https://req.test:8443/x?q=1', undefined)).toBe('https://req.test:8443');
	});
});
