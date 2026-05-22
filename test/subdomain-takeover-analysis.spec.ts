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

	describe('classifyTargetNamespace', () => {
		async function fn() {
			const m = await import('../packages/dns-checks/src/checks/subdomain-takeover-analysis');
			return m.classifyTargetNamespace;
		}

		it('classifies AWS NLB/ALB random-ID targets as "random"', async () => {
			const c = await fn();
			expect(c('ab74714963781430da5c4d9a29a6ee3c-1355387950.us-east-1.elb.amazonaws.com')).toBe('random');
			expect(c('a1234567890abcdef0123456789abcdef-0987654321.eu-west-1.elb.amazonaws.com')).toBe('random');
		});

		it('classifies CloudFront distribution IDs as "random"', async () => {
			const c = await fn();
			expect(c('d2b532lzynlqb7.cloudfront.net')).toBe('random');
			expect(c('e1abc23def45gh.cloudfront.net')).toBe('random');
		});

		it('classifies API Gateway IDs as "random"', async () => {
			const c = await fn();
			expect(c('a1b2c3d4e5.execute-api.us-east-1.amazonaws.com')).toBe('random');
		});

		it('classifies Azure Container Apps random-environment IDs as "random"', async () => {
			const c = await fn();
			expect(c('chatgpt-slack.jollybeach-2c1b6a13.centralus.azurecontainerapps.io')).toBe('random');
		});

		it('classifies user-chosen S3 bucket names as "claimable"', async () => {
			const c = await fn();
			expect(c('my-company-assets.s3.amazonaws.com')).toBe('claimable');
			expect(c('staging-bucket.s3.us-east-1.amazonaws.com')).toBe('claimable');
		});

		it('classifies user-chosen Azure endpoint names as "claimable"', async () => {
			const c = await fn();
			expect(c('openaiassets.afd.azureedge.net')).toBe('claimable');
			expect(c('mystorage.blob.core.windows.net')).toBe('claimable');
			expect(c('myapp.azurewebsites.net')).toBe('claimable');
		});

		it('classifies GitHub Pages / Heroku / Vercel as "claimable"', async () => {
			const c = await fn();
			expect(c('my-repo.github.io')).toBe('claimable');
			expect(c('my-app.herokuapp.com')).toBe('claimable');
			expect(c('preview-abc.vercel.app')).toBe('claimable');
		});

		it('returns "unknown" for non-takeover-service targets', async () => {
			const c = await fn();
			expect(c('lb.internal.example.com')).toBe('unknown');
			expect(c('some-random-cname.example.org')).toBe('unknown');
		});
	});

	describe('severity refinement by target claimability', () => {
		it('emits MEDIUM (not HIGH) when CNAME target is an AWS NLB random-ID', async () => {
			const dns = makeDNS({
				'models.example.com|CNAME': ['ab74714963781430da5c4d9a29a6ee3c-1355387950.us-east-1.elb.amazonaws.com.'],
				'ab74714963781430da5c4d9a29a6ee3c-1355387950.us-east-1.elb.amazonaws.com|A': [],
			});
			const fetchFn = vi.fn();
			const findings = await scanSubdomainForTakeover('example.com', 'models', dns, fetchFn);
			expect(findings).toHaveLength(1);
			expect(findings[0].severity).toBe('medium');
			expect(findings[0].metadata?.verificationStatus).toBe('potential');
			expect(findings[0].metadata?.severityRationale).toBe('random_target_id');
			expect(findings[0].detail).toContain('operational drift');
		});

		it('emits MEDIUM when CNAME target is a CloudFront distribution ID', async () => {
			const dns = makeDNS({
				'blog.example.com|CNAME': ['d2b532lzynlqb7.cloudfront.net.'],
				'd2b532lzynlqb7.cloudfront.net|A': [],
			});
			const findings = await scanSubdomainForTakeover('example.com', 'blog', dns, vi.fn());
			expect(findings[0].severity).toBe('medium');
			expect(findings[0].metadata?.severityRationale).toBe('random_target_id');
		});

		it('keeps HIGH when CNAME target is a user-chosen S3 bucket name', async () => {
			const dns = makeDNS({
				'assets.example.com|CNAME': ['my-company-assets.s3.amazonaws.com.'],
				'my-company-assets.s3.amazonaws.com|A': [],
			});
			const findings = await scanSubdomainForTakeover('example.com', 'assets', dns, vi.fn());
			expect(findings[0].severity).toBe('high');
			expect(findings[0].metadata?.severityRationale).toBe('claimable_target_name');
		});

		it('keeps HIGH (conservative default) when target namespace is unknown', async () => {
			const dns = makeDNS({
				'preview.example.com|CNAME': ['cname.vercel-dns.com.'],
				'cname.vercel-dns.com|A': [],
			});
			const findings = await scanSubdomainForTakeover('example.com', 'preview', dns, vi.fn());
			// vercel-dns.com IS in the takeover-services list → claimable
			expect(findings[0].severity).toBe('high');
			expect(findings[0].metadata?.severityRationale).toBe('claimable_target_name');
		});
	});

	describe('x.ai models cluster regression (TDD plan 2026-05-23)', () => {
		it('the 9 dangling models.x.ai subdomains all classify as MEDIUM operational drift', async () => {
			const NLB = 'ab74714963781430da5c4d9a29a6ee3c-1355387950.us-east-1.elb.amazonaws.com';
			// Full FQDNs — scanSubdomainForTakeover treats any dot-containing
			// `subdomain` arg as a full FQDN (CT-enumeration call shape).
			const subdomains = [
				'aurora-sglang.us-east-1.models.x.ai',
				'aurora-upsampler-sglang.us-east-1.models.x.ai',
				'enterprise-api-grok-2-1212.us-east-1.models.x.ai',
				'grok-3-5-code-0625.us-east-1.models.x.ai',
				'grok-4-code-0630.us-east-1.models.x.ai',
				'embedding-10m-0806-enterprise.us-east-1.models.x.ai',
				'fte5-embedding-0806-api.us-east-1.models.x.ai',
				'fte5-v2-fast-embedding-0806-api.us-east-1.models.x.ai',
				'fte5-embedding-250707-api.us-east-1.models.x.ai',
			];
			const dnsMap: Record<string, string[]> = { [`${NLB}|A`]: [] };
			for (const s of subdomains) {
				dnsMap[`${s}|CNAME`] = [`${NLB}.`];
			}
			const dns = makeDNS(dnsMap);

			const findings = (await Promise.all(subdomains.map((s) => scanSubdomainForTakeover('x.ai', s, dns, vi.fn())))).flat();

			expect(findings).toHaveLength(9);
			for (const f of findings) {
				expect(f.severity).toBe('medium');
				expect(f.metadata?.severityRationale).toBe('random_target_id');
			}
		});
	});
});
