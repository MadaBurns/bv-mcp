import { describe, expect, it, afterEach, vi } from 'vitest';
import { createDohResponse } from './helpers/dns-mock';

function cnameResponse(name: string, cname: string) {
	return createDohResponse(
		[{ name, type: 5 }],
		[{ name, type: 5, TTL: 300, data: `${cname}.` }],
	);
}

function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

describe('subdomain-takeover-analysis', () => {
	async function getModule() {
		return import('../src/tools/subdomain-takeover-analysis');
	}

	it('matches Heroku fingerprints during HTTP probing', async () => {
		const { probeHttpFingerprint } = await getModule();
		globalThis.fetch = vi.fn().mockResolvedValue(new Response('<html><body>No such app</body></html>', { status: 404 }));

		await expect(probeHttpFingerprint('app.example.com', 'old-app.herokuapp.com')).resolves.toBe('Heroku');
	});

	it('returns null when the CNAME has no supported fingerprint service', async () => {
		const { probeHttpFingerprint } = await getModule();
		globalThis.fetch = vi.fn();

		await expect(probeHttpFingerprint('app.example.com', 'lb.example.com')).resolves.toBeNull();
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it('returns a high-severity finding for unresolved third-party CNAME targets', async () => {
		const { scanSubdomainForTakeover } = await getModule();
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					return Promise.resolve(cnameResponse('preview.example.com', 'cname.vercel-dns.com'));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					return Promise.resolve(emptyResponse('cname.vercel-dns.com', 1));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const findings = await scanSubdomainForTakeover('example.com', 'preview');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('high');
		expect(findings[0].metadata?.verificationStatus).toBe('potential');
	});

	it('returns a critical finding for verified provider fingerprints', async () => {
		const { scanSubdomainForTakeover } = await getModule();
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					return Promise.resolve(cnameResponse('docs.example.com', 'example.github.io'));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					return Promise.resolve(aResponse('example.github.io', ['185.199.108.153']));
				}
			}

			return Promise.resolve(new Response("<html><body>There isn't a GitHub Pages site here.</body></html>", { status: 404 }));
		});

		const findings = await scanSubdomainForTakeover('example.com', 'docs');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('critical');
		expect(findings[0].title).toContain('GitHub Pages');
		expect(findings[0].metadata?.verificationStatus).toBe('verified');
	});

	it('builds the stable no-takeover info finding', async () => {
		const { getNoTakeoverFinding } = await getModule();
		const finding = getNoTakeoverFinding('example.com');

		expect(finding.severity).toBe('info');
		expect(finding.title).toBe('No dangling CNAME records found');
		expect(finding.metadata?.verificationStatus).toBe('not_exploitable');
	});
});