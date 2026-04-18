// SPDX-License-Identifier: BUSL-1.1
import type { Context } from 'hono';
import { RegisterRequestSchema } from '../schemas/oauth';
import { OAUTH_REDIRECT_URI_ALLOWLIST } from '../lib/config';
import { putClient } from './storage';

const MAX_BODY_BYTES = 4 * 1024;

export async function handleRegister(c: Context): Promise<Response> {
	const ct = c.req.header('content-type') ?? '';
	if (!ct.toLowerCase().includes('application/json')) {
		return c.json({ error: 'invalid_request', error_description: 'Content-Type must be application/json' }, 415);
	}
	const raw = await c.req.raw.clone().text();
	if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
		return c.json({ error: 'invalid_request', error_description: 'Body exceeds 4 KB' }, 413);
	}

	let parsed;
	try {
		parsed = RegisterRequestSchema.parse(JSON.parse(raw));
	} catch (err) {
		return c.json({ error: 'invalid_client_metadata', error_description: (err as Error).message }, 400);
	}

	for (const uri of parsed.redirect_uris) {
		if (!OAUTH_REDIRECT_URI_ALLOWLIST.some((re) => re.test(uri))) {
			return c.json({ error: 'invalid_redirect_uri', error_description: `redirect_uri not allowed: ${uri}` }, 400);
		}
	}

	const client_id = crypto.randomUUID();
	const rec = {
		client_id,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		redirect_uris: parsed.redirect_uris,
		client_name: parsed.client_name,
		software_id: parsed.software_id,
		software_version: parsed.software_version,
	};
	const kv = (c.env as { SESSION_STORE: KVNamespace }).SESSION_STORE;
	await putClient(kv, rec);

	return c.json(
		{
			client_id,
			client_id_issued_at: rec.client_id_issued_at,
			redirect_uris: rec.redirect_uris,
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code'],
			response_types: ['code'],
		},
		201,
	);
}
