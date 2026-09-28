// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Fetch router: DoH (any URL carrying ?name=), the two documents, registries, OSV,
// and takeover fingerprint/robots probes. Every call is recorded so a test can
// assert on egress.
// ---------------------------------------------------------------------------

const TYPE_CODE: Record<string, number> = { A: 1, CNAME: 5, AAAA: 28 };

interface Routes {
	/** Document path on the scanned domain → response factory. Missing → 404. */
	docs?: Record<string, () => Response>;
	/** Host → CNAME target (no trailing dot). */
	cnames?: Record<string, string>;
	/** Name → A records. Missing → empty answer. */
	a?: Record<string, string[]>;
	/** npm package → HTTP status. Missing → 404. */
	npm?: Record<string, number>;
	/** PyPI project → HTTP status. Missing → 404. */
	pypi?: Record<string, number>;
	/** Package name → OSV ids, or a factory for a failing OSV. */
	osv?: Record<string, string[]> | (() => Response);
}

function mockWeb(domain: string, routes: Routes) {
	const calls: Array<{ url: string; method: string }> = [];
	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request, init?: RequestInit) => {
		const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		calls.push({ url: href, method: init?.method ?? 'GET' });
		const u = new URL(href);

		const name = u.searchParams.get('name');
		if (name !== null) {
			const rawType = u.searchParams.get('type') ?? 'A';
			const type = TYPE_CODE[rawType] ?? Number(rawType);
			const q = [{ name, type }];
			if (type === 5 && routes.cnames?.[name]) {
				return createDohResponse(q, [{ name, type: 5, TTL: 300, data: `${routes.cnames[name]}.` }]);
			}
			if (type === 1 && routes.a?.[name]) {
				return createDohResponse(
					q,
					routes.a[name].map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
				);
			}
			return createDohResponse(q, []);
		}

		if (u.hostname === domain) {
			const route = routes.docs?.[u.pathname];
			return route ? route() : new Response('not found', { status: 404 });
		}
		if (u.hostname === 'registry.npmjs.org') {
			const pkg = decodeURIComponent(u.pathname.slice(1));
			return new Response('{}', { status: routes.npm?.[pkg] ?? 404 });
		}
		if (u.hostname === 'pypi.org') {
			const pkg = decodeURIComponent(u.pathname.split('/')[2] ?? '');
			return new Response('{}', { status: routes.pypi?.[pkg] ?? 404 });
		}
		if (href === 'https://api.osv.dev/v1/querybatch') {
			if (typeof routes.osv === 'function') return routes.osv();
			const body = JSON.parse(String(init?.body ?? '{}')) as { queries: Array<{ package: { name: string } }> };
			const table = routes.osv ?? {};
			return Response.json({
				results: body.queries.map((q) => {
					const ids = table[q.package.name] ?? [];
					return ids.length > 0 ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
				}),
			});
		}
		// Takeover robots.txt / fingerprint probes: nothing matches a provider fingerprint.
		return new Response('not found', { status: 404 });
	});
	return calls;
}

const FIXTURE = [
	'# Example',
	'',
	'> Example documentation for agents.',
	'',
	'## Docs',
	'- [Guide](https://example.com/docs/guide.md): same-origin guide',
	'- [API](/docs/api.md): relative link',
	'- [Old docs](https://docs.example.com/start): host with a dangling CNAME',
	'- [Source](https://github.com/example/repo)',
	'See also https://github.com/example/repo#readme and https://example.com/docs/guide.md#top.',
	'',
	'## Install',
	'```bash',
	'npm install ghost-pkg-llms-fixture',
	'npm i -D evil-pkg-llms-fixture@1.0.0 left-pad',
	'```',
	'Run npm install to get started.',
].join('\n');

async function run(domain = 'example.com') {
	const { checkLlmsTxt } = await import('../src/tools/check-llms-txt');
	return checkLlmsTxt(domain);
}

describe('checkLlmsTxt', () => {
	it('flags a dangling link host, an unregistered package and an OSV MAL hit from one llms.txt', async () => {
		const calls = mockWeb('example.com', {
			docs: { '/llms.txt': () => new Response(FIXTURE, { status: 200, headers: { 'content-type': 'text/plain' } }) },
			cnames: { 'docs.example.com': 'old-docs.herokuapp.com' },
			a: { 'github.com': ['140.82.112.3'] },
			npm: { 'evil-pkg-llms-fixture': 200, 'left-pad': 200 },
			osv: { 'evil-pkg-llms-fixture': ['MAL-2025-0001'] },
		});

		const result = await run();

		expect(result.category).toBe('llms_txt');
		// Each document is classified on its own; /llms-full.txt is the 404 case.
		expect(result.documents.map((d) => [d.path, d.status])).toEqual([
			['/llms.txt', 'found'],
			['/llms-full.txt', 'not_found'],
		]);
		expect(result.documents[1].httpStatus).toBe(404);

		// Links: normalised (fragment stripped, relative resolved), deduped, tagged.
		expect(result.links).toEqual([
			{ url: 'https://example.com/docs/guide.md', scope: 'same-origin' },
			{ url: 'https://example.com/docs/api.md', scope: 'same-origin' },
			{ url: 'https://docs.example.com/start', scope: 'external' },
			{ url: 'https://github.com/example/repo', scope: 'external' },
		]);
		expect(result.externalHosts.swept).toEqual(['docs.example.com', 'github.com']);

		// Dangling CNAME — worded as evidence, not proof of claimability.
		const dangling = result.findings.find((f) => f.title.includes('docs.example.com') && f.severity === 'high');
		expect(dangling).toBeDefined();
		expect(dangling!.title).toContain('herokuapp.com');
		expect(dangling!.detail).toContain('not proof that the name can be claimed');
		expect(dangling!.metadata?.verificationStatus).toBe('potential');

		// Unregistered npm name → high.
		const missing = result.findings.find((f) => f.title === 'Referenced package is not registered: npm:ghost-pkg-llms-fixture');
		expect(missing?.severity).toBe('high');

		// OSV MAL- id → critical.
		const mal = result.findings.find((f) => f.severity === 'critical');
		expect(mal?.title).toContain('npm:evil-pkg-llms-fixture');
		expect(mal?.detail).toContain('MAL-2025-0001');

		// Prose outside code ("npm install to get started") is not read as a command.
		expect(result.packages.map((p) => p.name)).toEqual(['ghost-pkg-llms-fixture', 'evil-pkg-llms-fixture', 'left-pad']);
		const leftPad = result.packages.find((p) => p.name === 'left-pad');
		expect(leftPad).toMatchObject({ registry: 'present', osv: 'no_malicious_advisory' });
		expect(result.findings.some((f) => f.detail.includes('not a safety signal'))).toBe(true);

		// Never a boolean "safe" verdict, and the not-assessed member is always present.
		expect(Object.keys(result)).not.toContain('safe');
		for (const p of result.packages) expect(Object.keys(p)).not.toContain('safe');
		expect(result.notAssessed).toEqual([]);

		// Every egress is https (safeFetch blocks the takeover sweep's http:// fallback before fetch).
		expect(calls.every((c) => c.url.startsWith('https://'))).toBe(true);
	});

	it('classifies an oversized llms.txt as too_large and abstains instead of passing', async () => {
		const calls = mockWeb('example.com', {
			docs: { '/llms.txt': () => new Response('a'.repeat(256 * 1024 + 1), { status: 200 }) },
		});

		const result = await run();

		expect(result.documents[0].status).toBe('too_large');
		expect(result.documents[1].status).toBe('not_found');
		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.passed).toBe(false);
		expect(result.notAssessed).toContainEqual({ target: '/llms.txt', reason: expect.stringContaining('read cap') });
		// Nothing was parsed, so nothing downstream was probed.
		expect(calls.map((c) => new URL(c.url).hostname)).toEqual(['example.com', 'example.com']);
	});

	it('reports a measured absence when neither document exists', async () => {
		const calls = mockWeb('example.com', {});

		const result = await run();

		expect(result.documents.map((d) => d.status)).toEqual(['not_found', 'not_found']);
		expect(result.findings[0].title).toBe('No llms.txt published');
		expect(result.checkStatus).toBeUndefined();
		expect(result.notAssessed).toEqual([]);
		expect(calls).toHaveLength(2);
	});

	it('classifies a redirect without following it and names the host to re-run against', async () => {
		const calls = mockWeb('example.com', {
			docs: {
				'/llms.txt': () => new Response(null, { status: 301, headers: { location: 'https://www.example.com/llms.txt' } }),
				'/llms-full.txt': () => new Response(null, { status: 301, headers: { location: 'https://www.example.com/llms-full.txt' } }),
			},
		});

		const result = await run();

		expect(result.documents[0]).toMatchObject({ status: 'redirect', httpStatus: 301, location: 'https://www.example.com/llms.txt' });
		expect(result.checkStatus).toBe('error');
		expect(result.notAssessed[0].reason).toContain('re-run check_llms_txt against www.example.com');
		expect(calls.some((c) => c.url.startsWith('https://www.example.com'))).toBe(false);
	});

	it('treats an HTML page served at /llms.txt as a soft 404', async () => {
		mockWeb('example.com', {
			docs: { '/llms.txt': () => new Response('<!doctype html><html><body>app</body></html>', { status: 200 }) },
		});

		const result = await run();

		expect(result.documents[0]).toMatchObject({ status: 'not_found', softNotFound: true });
		expect(result.links).toEqual([]);
	});

	it('lists OSV as not assessed (never clean) when OSV is unavailable', async () => {
		mockWeb('example.com', {
			docs: { '/llms.txt': () => new Response('```\npip install requests\n```', { status: 200 }) },
			pypi: { requests: 200 },
			osv: () => new Response('upstream error', { status: 503 }),
		});

		const result = await run();

		expect(result.packages).toEqual([{ ecosystem: 'PyPI', name: 'requests', registry: 'present', osv: 'not_assessed' }]);
		expect(result.notAssessed).toContainEqual({ target: 'osv', reason: expect.stringContaining('HTTP 503') });
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.title.includes('no OSV malicious-package advisory'))).toBe(false);
	});

	it('caps links at 200 and reports the truncation', async () => {
		const body = Array.from({ length: 250 }, (_, i) => `- [p${i}](https://example.com/p/${i})`).join('\n');
		mockWeb('example.com', { docs: { '/llms.txt': () => new Response(body, { status: 200 }) } });

		const result = await run();

		expect(result.links).toHaveLength(200);
		expect(result.linkSummary).toMatchObject({ discovered: 250, assessed: 200, truncated: true });
		expect(result.notAssessed).toContainEqual({ target: 'links', reason: expect.stringContaining('200-link cap') });
	});

	it('never sweeps IP-literal or non-public link hosts', async () => {
		const calls = mockWeb('example.com', {
			docs: { '/llms.txt': () => new Response('- [a](https://127.0.0.1/x)\n- [b](https://localhost/y)', { status: 200 }) },
		});

		const result = await run();

		expect(result.externalHosts.swept).toEqual([]);
		expect(result.notAssessed).toContainEqual({ target: 'hosts', reason: expect.stringContaining('IP literals or non-public names') });
		expect(calls.some((c) => /127\.0\.0\.1|localhost/.test(c.url))).toBe(false);
	});

	it('parses cap-sized pathological documents without quadratic backtracking', async () => {
		// Just under the 256 KiB cap: a run of unclosed `[` (markdown-link scan) and a run of
		// unclosed fence openers (code-fence scan). The unbounded patterns took tens of seconds
		// of CPU on these inputs, so a regression surfaces as this test timing out.
		const cap = 256 * 1024;
		mockWeb('example.com', {
			docs: {
				'/llms.txt': () => new Response('['.repeat(cap - 1), { status: 200 }),
				'/llms-full.txt': () => new Response('```a\n'.repeat(Math.floor((cap - 1) / 5)), { status: 200 }),
			},
		});

		const result = await run();

		expect(result.documents.map((d) => d.status)).toEqual(['found', 'found']);
		expect(result.links).toEqual([]);
		expect(result.packages).toEqual([]);
	});

	it('extracts package names across the supported install commands', async () => {
		const body = [
			'```sh',
			'pnpm add zod',
			'yarn add react@^18',
			'npx -y @modelcontextprotocol/server-filesystem /tmp',
			'pip install -U "Flask[async]>=3.0" -r requirements.txt',
			'uv add httpx',
			'pipx install black',
			'```',
		].join('\n');
		mockWeb('example.com', {
			docs: { '/llms.txt': () => new Response(body, { status: 200 }) },
			npm: { zod: 200, react: 200, '@modelcontextprotocol/server-filesystem': 200 },
			pypi: { flask: 200, httpx: 200, black: 200 },
		});

		const result = await run();

		expect(result.packages.map((p) => `${p.ecosystem}:${p.name}`)).toEqual([
			'npm:zod',
			'npm:react',
			'npm:@modelcontextprotocol/server-filesystem',
			'PyPI:flask',
			'PyPI:httpx',
			'PyPI:black',
		]);
		expect(result.packages.every((p) => p.registry === 'present')).toBe(true);
	});
});

describe('check_llms_txt registration', () => {
	it('is a standalone, non-scoring intelligence tool', async () => {
		const { TOOLS } = await import('../src/schemas/tool-definitions');
		const tool = TOOLS.find((t) => t.name === 'check_llms_txt');
		expect(tool).toBeDefined();
		expect(tool).toMatchObject({ group: 'intelligence', scanIncluded: false });
		expect(tool?.tier).toBeUndefined();
		// Out of the scoring union, so it can never enter a scan score or grade.
		const { CATEGORY_TIERS } = await import('@blackveil/dns-checks');
		expect(Object.keys(CATEGORY_TIERS)).not.toContain('llms_txt');
	});
});
