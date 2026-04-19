import { describe, expect, it } from 'vitest';

describe('oauth schemas', () => {
	it('RegisterRequestSchema accepts minimal valid body', async () => {
		const { RegisterRequestSchema } = await import('../../src/schemas/oauth');
		const parsed = RegisterRequestSchema.parse({
			redirect_uris: ['https://claude.ai/cb'],
			client_name: 'Claude',
		});
		expect(parsed.token_endpoint_auth_method).toBe('none');
	});

	it('RegisterRequestSchema rejects missing redirect_uris', async () => {
		const { RegisterRequestSchema } = await import('../../src/schemas/oauth');
		expect(() => RegisterRequestSchema.parse({ client_name: 'x' })).toThrow();
	});

	it('AuthorizeQuerySchema rejects missing PKCE', async () => {
		const { AuthorizeQuerySchema } = await import('../../src/schemas/oauth');
		expect(() =>
			AuthorizeQuerySchema.parse({
				client_id: 'c',
				redirect_uri: 'https://claude.ai/cb',
				response_type: 'code',
				state: 's',
			}),
		).toThrow(/code_challenge/);
	});

	it('AuthorizeQuerySchema rejects plain PKCE method', async () => {
		const { AuthorizeQuerySchema } = await import('../../src/schemas/oauth');
		expect(() =>
			AuthorizeQuerySchema.parse({
				client_id: 'c',
				redirect_uri: 'https://claude.ai/cb',
				response_type: 'code',
				state: 's',
				code_challenge: 'x',
				code_challenge_method: 'plain',
			}),
		).toThrow();
	});

	it('TokenRequestSchema accepts authorization_code grant', async () => {
		const { TokenRequestSchema } = await import('../../src/schemas/oauth');
		const parsed = TokenRequestSchema.parse({
			grant_type: 'authorization_code',
			code: 'abc',
			redirect_uri: 'https://claude.ai/cb',
			client_id: 'c',
			code_verifier: 'v'.repeat(43),
		});
		expect(parsed.grant_type).toBe('authorization_code');
	});
});
