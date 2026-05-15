// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the R2 signed-URL helper.
 *
 * Cloudflare R2 bucket bindings expose `createSignedUrl` (in beta on the Workers
 * runtime). For environments where that's not available, the helper falls back
 * to AWS-SigV4-style presigning using R2 access keys passed in via env. The
 * shipped path uses the binding-native call.
 */

import { describe, it, expect, vi } from 'vitest';

describe('generateR2SignedUrl', () => {
	it('delegates to bucket.createSignedUrl when available', async () => {
		const { generateR2SignedUrl } = await import('../src/lib/r2-signed-url');
		const createSignedUrl = vi.fn().mockResolvedValue('https://r2.example.com/signed-url?token=abc');
		const bucket = { createSignedUrl } as unknown as R2Bucket;

		const url = await generateR2SignedUrl(bucket, 'audits/aud-1/apple.com.pdf', 3600);
		expect(url).toBe('https://r2.example.com/signed-url?token=abc');
		expect(createSignedUrl).toHaveBeenCalledWith({
			key: 'audits/aud-1/apple.com.pdf',
			expiresInSeconds: 3600,
		});
	});

	it('defaults TTL to 7 days when omitted', async () => {
		const { generateR2SignedUrl } = await import('../src/lib/r2-signed-url');
		const createSignedUrl = vi.fn().mockResolvedValue('https://r2.example.com/x');
		const bucket = { createSignedUrl } as unknown as R2Bucket;

		await generateR2SignedUrl(bucket, 'audits/aud-1/_summary.pdf');
		expect(createSignedUrl).toHaveBeenCalledWith({
			key: 'audits/aud-1/_summary.pdf',
			expiresInSeconds: 604800,
		});
	});

	it('throws when the bucket has no createSignedUrl method (binding misconfigured)', async () => {
		const { generateR2SignedUrl } = await import('../src/lib/r2-signed-url');
		const bucket = {} as unknown as R2Bucket;
		await expect(generateR2SignedUrl(bucket, 'audits/aud-1/apple.com.pdf')).rejects.toThrow(/createSignedUrl/);
	});

	it('rejects empty / overlong keys to defend against path traversal', async () => {
		const { generateR2SignedUrl } = await import('../src/lib/r2-signed-url');
		const createSignedUrl = vi.fn();
		const bucket = { createSignedUrl } as unknown as R2Bucket;

		await expect(generateR2SignedUrl(bucket, '')).rejects.toThrow(/invalid R2 key/);
		await expect(generateR2SignedUrl(bucket, '../etc/passwd')).rejects.toThrow(/invalid R2 key/);
		await expect(generateR2SignedUrl(bucket, 'a'.repeat(1025))).rejects.toThrow(/invalid R2 key/);
		expect(createSignedUrl).not.toHaveBeenCalled();
	});
});
