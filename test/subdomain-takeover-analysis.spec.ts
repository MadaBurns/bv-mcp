// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, afterEach, vi } from 'vitest';
import {
	probeHttpFingerprint,
	scanSubdomainForTakeover,
	getNoTakeoverFinding,
} from '../packages/dns-checks/src/checks/subdomain-takeover-analysis';

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

/** Build a queryDNS stub keyed by `${name}|${type}` → records. */
function makeDNS(map: Record<string, string[]>) {
	return async (name: string, type: string): Promise<string[]> => {
		const k = `${name}|${type}`;
		return map[k] ?? [];
	};
}

/** fetch-stub returning a Response whose body matches the deprovision fingerprint. */
function fetchReturning(body: string, status = 404) {
	return vi.fn(async (_req: unknown, _init?: unknown) => new Response(body, { status }));
}

describe('subdomain-takeover-analysis', () => {
	it('matches Heroku fingerprint during HTTP probing', async () => {
		const fetchFn = fetchReturning('<html><body>No such app</body></html>');
		await expect(probeHttpFingerprint('app.example.com', 'old-app.herokuapp.com', fetchFn)).resolves.toBe('Heroku');
	});

	it('returns null when the CNAME does not match any known takeover service', async () => {
		const fetchFn = vi.fn();
		await expect(probeHttpFingerprint('app.example.com', 'lb.example.com', fetchFn)).resolves.toBeNull();
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('returns high-severity finding when CNAME target does not resolve', async () => {
		const dns = makeDNS({
			'preview.example.com|CNAME': ['cname.vercel-dns.com.'],
			'cname.vercel-dns.com|A': [],
		});
		const fetchFn = vi.fn();
		const findings = await scanSubdomainForTakeover('example.com', 'preview', dns, fetchFn);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('high');
		expect(findings[0].metadata?.verificationStatus).toBe('potential');
	});

	it('returns critical finding when CNAME target resolves AND fingerprint matches', async () => {
		const dns = makeDNS({
			'docs.example.com|CNAME': ['example.github.io.'],
			'example.github.io|A': ['185.199.108.153'],
		});
		const fetchFn = fetchReturning("<html><body>There isn't a GitHub Pages site here.</body></html>");
		const findings = await scanSubdomainForTakeover('example.com', 'docs', dns, fetchFn);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('critical');
		expect(findings[0].title).toContain('GitHub Pages');
		expect(findings[0].metadata?.verificationStatus).toBe('verified');
	});

	it('builds the stable no-takeover info finding', () => {
		const finding = getNoTakeoverFinding('example.com');
		expect(finding.severity).toBe('info');
		expect(finding.title).toBe('No dangling CNAME records found');
		expect(finding.metadata?.verificationStatus).toBe('not_exploitable');
	});

	describe('expanded fingerprint dictionary (PR #180)', () => {
		it('matches Azure Front Door / CDN ResourceNotFound (cdn.openai.com pattern)', async () => {
			const body =
				'<?xml version="1.0" encoding="utf-8"?><Error><Code>ResourceNotFound</Code><Message>The specified resource does not exist.</Message></Error>';
			const fetchFn = fetchReturning(body);
			const result = await probeHttpFingerprint('cdn.example.com', 'example-assets.afd.azureedge.net', fetchFn);
			expect(result).toBe('Azure Front Door');
		});

		it('matches Azure CDN ResourceNotFound', async () => {
			const fetchFn = fetchReturning('<Code>ResourceNotFound</Code>');
			const result = await probeHttpFingerprint('static.example.com', 'example.azureedge.net', fetchFn);
			expect(result).toBe('Azure CDN');
		});

		it('matches Azure Blob BlobNotFound', async () => {
			const fetchFn = fetchReturning('<Code>BlobNotFound</Code><Message>The specified blob does not exist.</Message>');
			const result = await probeHttpFingerprint('assets.example.com', 'mystorage.blob.core.windows.net', fetchFn);
			expect(result).toBe('Azure Blob Storage');
		});

		it('matches Azure App Service "404 Web Site not found"', async () => {
			const fetchFn = fetchReturning('<html><head><title>404 Web Site not found</title></head><body></body></html>');
			const result = await probeHttpFingerprint('app.example.com', 'example-app.azurewebsites.net', fetchFn);
			expect(result).toBe('Azure App Service');
		});

		it('matches GCP Cloud Storage NoSuchBucket', async () => {
			const fetchFn = fetchReturning('<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code></Error>');
			const result = await probeHttpFingerprint('cdn.example.com', 'example-assets.storage.googleapis.com', fetchFn);
			expect(result).toBe('GCP Cloud Storage');
		});

		it('matches Shopify deprovisioned storefront', async () => {
			const fetchFn = fetchReturning('<title>Sorry, this shop is currently unavailable.</title>');
			const result = await probeHttpFingerprint('shop.example.com', 'example-store.myshopify.com', fetchFn);
			expect(result).toBe('Shopify');
		});

		it('matches Vercel DEPLOYMENT_NOT_FOUND', async () => {
			const fetchFn = fetchReturning('<title>404: NOT_FOUND</title>DEPLOYMENT_NOT_FOUND');
			const result = await probeHttpFingerprint('preview.example.com', 'example.vercel.app', fetchFn);
			expect(result).toBe('Vercel');
		});

		it('matches Firebase Hosting Site Not Found', async () => {
			const fetchFn = fetchReturning('<h1>Site Not Found</h1>The requested project has been deleted.');
			const result = await probeHttpFingerprint('app.example.com', 'example-project.firebaseapp.com', fetchFn);
			expect(result).toBe('Firebase Hosting');
		});

		it('returns null on Azure CDN active endpoint (no ResourceNotFound)', async () => {
			const fetchFn = fetchReturning('<html><body>Active content here</body></html>', 200);
			const result = await probeHttpFingerprint('cdn.example.com', 'example-assets.azureedge.net', fetchFn);
			expect(result).toBeNull();
		});
	});
});
