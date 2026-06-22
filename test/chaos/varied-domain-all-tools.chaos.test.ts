// SPDX-License-Identifier: BUSL-1.1
//
// All-tools chaos spine for the MCP domain scanner. The point is not to assert
// exact security scores; it is to keep every registered tool callable through
// the production dispatcher across varied, deterministic domain fixtures.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../../src/lib/cache';
import { handleToolsCall } from '../../src/handlers/tools';
import { TOOLS } from '../../src/schemas/tool-definitions';
import { createDohResponse } from '../helpers/dns-mock';

const DOMAIN_VARIANTS = [
	'secure.example.com',
	'lax-mail.example.org',
	'brand-example.net',
	'hyphenated-edge.example.com',
	'xn--bcher-kva.example.com',
] as const;

type ToolCase = {
	name: string;
	arguments: Record<string, unknown>;
};

type ToolResult = Awaited<ReturnType<typeof handleToolsCall>>;

const TYPE_CODE: Record<string, number> = {
	A: 1,
	NS: 2,
	CNAME: 5,
	SOA: 6,
	PTR: 12,
	MX: 15,
	TXT: 16,
	AAAA: 28,
	SRV: 33,
	DS: 43,
	DNSKEY: 48,
	NSEC3PARAM: 51,
	TLSA: 52,
	SVCB: 64,
	HTTPS: 65,
	CAA: 257,
};

const TYPE_NAME_BY_CODE = Object.fromEntries(Object.entries(TYPE_CODE).map(([name, code]) => [String(code), name]));

function apex(domain: string): string {
	const labels = domain.replace(/\.$/, '').split('.');
	return labels.slice(-2).join('.');
}

function textResponse(body: string, status = 200, headers?: Headers): Response {
	const responseHeaders =
		headers ??
		new Headers({
			'content-security-policy': "default-src 'self'",
			'cross-origin-opener-policy': 'same-origin',
			'cross-origin-resource-policy': 'same-origin',
			'permissions-policy': 'geolocation=()',
			'referrer-policy': 'no-referrer',
			'strict-transport-security': 'max-age=31536000; includeSubDomains',
			'x-content-type-options': 'nosniff',
			'x-frame-options': 'DENY',
		});
	return {
		ok: status >= 200 && status < 300,
		status,
		url: 'https://chaos.local/',
		headers: responseHeaders,
		text: () => Promise.resolve(body),
		json: () => Promise.resolve(JSON.parse(body || '{}')),
	} as unknown as Response;
}

function jsonResponse(body: unknown, status = 200): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		url: 'https://chaos.local/',
		headers: new Headers({ 'content-type': 'application/json' }),
		text: () => Promise.resolve(JSON.stringify(body)),
		json: () => Promise.resolve(body),
	} as unknown as Response;
}

function emptyDoh(name: string, type: string): Response {
	return createDohResponse([{ name, type: TYPE_CODE[type] ?? 1 }], []);
}

function dohAnswers(name: string, type: string): Array<{ name: string; type: number; TTL: number; data: string }> {
	const normalized = name.toLowerCase().replace(/\.$/, '');
	const recordType = TYPE_CODE[type] ?? 1;
	const root = apex(normalized);

	if (type === 'TXT') {
		if (normalized.endsWith('.origin.asn.cymru.com')) {
			return [{ name, type: recordType, TTL: 300, data: '"13335 | 104.16.0.0/12 | US | arin | 2014-03-28"' }];
		}
		if (normalized === 'as13335.asn.cymru.com') {
			return [{ name, type: recordType, TTL: 300, data: '"13335 | US | arin | 2010-07-14 | CLOUDFLARENET"' }];
		}
		if (normalized.startsWith('_dmarc.')) {
			const policy = normalized.includes('lax-mail') ? 'p=none' : 'p=reject; rua=mailto:dmarc@' + root;
			return [{ name, type: recordType, TTL: 300, data: `"v=DMARC1; ${policy}"` }];
		}
		if (normalized.includes('._domainkey.')) {
			return [{ name, type: recordType, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"' }];
		}
		if (normalized.startsWith('_mta-sts.')) {
			return [{ name, type: recordType, TTL: 300, data: '"v=STSv1; id=20260516"' }];
		}
		if (normalized.startsWith('_smtp._tls.')) {
			return [{ name, type: recordType, TTL: 300, data: '"v=TLSRPTv1; rua=mailto:tlsrpt@' + root + '"' }];
		}
		if (normalized.startsWith('default._bimi.')) {
			return [{ name, type: recordType, TTL: 300, data: '"v=BIMI1; l=https://brand-example.net/logo.svg"' }];
		}
		if (normalized === '_spf.google.com') {
			return [{ name, type: recordType, TTL: 300, data: '"v=spf1 ip4:192.0.2.0/24 -all"' }];
		}
		return [{ name, type: recordType, TTL: 300, data: '"v=spf1 include:_spf.google.com mx -all"' }];
	}

	if (type === 'MX') {
		return [{ name, type: recordType, TTL: 300, data: `10 mx1.${root}.` }];
	}
	if (type === 'NS') {
		return [
			{ name, type: recordType, TTL: 300, data: 'ns1.shared-dns.example.' },
			{ name, type: recordType, TTL: 300, data: 'ns2.shared-dns.example.' },
		];
	}
	if (type === 'SOA') {
		return [{ name, type: recordType, TTL: 300, data: `ns1.${root}. hostmaster.${root}. 2026051601 3600 600 604800 300` }];
	}
	if (type === 'CAA') {
		return [{ name, type: recordType, TTL: 300, data: '0 issue "letsencrypt.org"' }];
	}
	if (type === 'A') {
		if (
			/\.(dbl\.spamhaus\.org|multi\.uribl\.com|multi\.surbl\.org|zen\.spamhaus\.org|bl\.spamcop\.net|uceprotect\.net|mailspike\.net|b\.barracudacentral\.org|psbl\.surriel\.com|dnsbl\.sorbs\.net)$/.test(
				normalized,
			)
		) {
			return [];
		}
		return [
			{
				name,
				type: recordType,
				TTL: normalized.includes('flux') ? 30 : 300,
				data: normalized.startsWith('mx1.') ? '198.51.100.25' : '192.0.2.10',
			},
		];
	}
	if (type === 'AAAA') {
		return [];
	}
	if (type === 'CNAME') {
		return [{ name, type: recordType, TTL: 300, data: `edge.${root}.` }];
	}
	if (type === 'SRV') {
		return [{ name, type: recordType, TTL: 300, data: `0 5 443 service.${root}.` }];
	}
	if (type === 'TLSA') {
		return [{ name, type: recordType, TTL: 300, data: '3 1 1 2A569FAD7B5F7E6B8F1E5EFD8A8A3F4B6C7D8E9F00112233445566778899AABB' }];
	}
	if (type === 'HTTPS' || type === 'SVCB') {
		return [{ name, type: recordType, TTL: 300, data: '1 . alpn="h2" ipv4hint=192.0.2.10' }];
	}
	if (type === 'NSEC3PARAM') {
		return [{ name, type: recordType, TTL: 300, data: '1 0 12 AABBCCDD' }];
	}

	return [];
}

function dohResponseFor(url: string): Response {
	const parsed = new URL(url);
	const name = parsed.searchParams.get('name') ?? 'example.com';
	const rawType = parsed.searchParams.get('type') ?? 'A';
	const type = (TYPE_NAME_BY_CODE[rawType] ?? rawType).toUpperCase();
	const answers = dohAnswers(name, type);
	return answers.length > 0 ? createDohResponse([{ name, type: TYPE_CODE[type] ?? 1 }], answers) : emptyDoh(name, type);
}

function rdapDomainResponse(domain: string): Response {
	return jsonResponse({
		ldhName: domain.toUpperCase(),
		status: ['active'],
		events: [
			{ eventAction: 'registration', eventDate: '2010-01-01T00:00:00Z' },
			{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' },
		],
		entities: [
			{
				roles: ['registrar'],
				vcardArray: ['vcard', [['fn', {}, 'text', domain.includes('brand') ? 'MarkMonitor Inc.' : 'Example Registrar LLC']]],
			},
			{
				roles: ['registrant'],
				vcardArray: ['vcard', [['fn', {}, 'text', domain.includes('brand') ? 'Brand Example Ltd' : 'Example Org']]],
			},
		],
	});
}

function installChaosFetch(): void {
	globalThis.fetch = vi.fn(async (input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com') || url.includes('dns.google') || url.includes('/dns-query') || url.includes('/resolve')) {
			return dohResponseFor(url);
		}

		if (url.includes('data.iana.org/rdap/dns.json')) {
			return jsonResponse({ services: [[['com', 'org', 'net'], ['https://rdap.chaos.test/']]] });
		}
		if (url.includes('rdap.chaos.test')) {
			const domain = decodeURIComponent(url.split('/domain/').pop() ?? 'example.com');
			return rdapDomainResponse(domain);
		}

		if (url.includes('crt.sh')) {
			return jsonResponse([
				{
					name_value: 'www.brand-example.net\nlogin.brand-example.net\napi.brand-example.net',
					issuer_name: "C=US, O=Let's Encrypt, CN=R3",
					not_before: '2026-01-01T00:00:00Z',
					not_after: '2030-01-01T00:00:00Z',
				},
			]);
		}

		if (url.includes('/.well-known/mta-sts.txt')) {
			return textResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400');
		}

		return textResponse('<!doctype html><title>Chaos Fixture</title><body>ok</body>');
	}) as unknown as typeof fetch;
}

function makeCertstreamBinding(): { fetch: typeof fetch } {
	return {
		fetch: vi.fn(async (input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const domain = new URL(url).searchParams.get('domain') ?? 'example.com';
			if (url.includes('/sans')) {
				return jsonResponse({
					domain,
					names: [`www.${domain}`, `login.${domain}`, 'brand-example.net', 'secure-example.com'],
					timedOut: false,
					cached: true,
				});
			}
			return jsonResponse({
				domain,
				subdomains: [`www.${domain}`, `api.${domain}`, `staging.${domain}`, `*.wild.${domain}`],
				certificateCount: 4,
				timedOut: false,
				cached: true,
			});
		}) as unknown as typeof fetch,
	};
}

function makeWhoisBinding(): { fetch: typeof fetch } {
	return {
		fetch: vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as { domain?: string }) : {};
			const registrar = body.domain?.includes('brand') ? 'MarkMonitor Inc.' : 'Example Registrar LLC';
			return jsonResponse({ registrar, source: 'whois' });
		}) as unknown as typeof fetch,
	};
}

function makeToolCases(): ToolCase[] {
	const baselineScore = JSON.stringify({
		overall: 55,
		grade: 'C',
		categoryScores: { spf: 30, dmarc: 30, dkim: 20, dnssec: 0 },
		findings: [{ category: 'dmarc', title: 'Baseline DMARC weak', severity: 'high', detail: 'Historical p=none' }],
	});
	const baseDomains = [...DOMAIN_VARIANTS];
	let cursor = 0;
	const nextDomain = () => baseDomains[cursor++ % baseDomains.length];
	const domainArgs = () => ({ domain: nextDomain(), format: 'compact' });

	return [
		{ name: 'check_mx', arguments: domainArgs() },
		{ name: 'check_spf', arguments: domainArgs() },
		{ name: 'check_dmarc', arguments: domainArgs() },
		{ name: 'check_dkim', arguments: { ...domainArgs(), selector: 'default' } },
		{ name: 'check_dnssec', arguments: domainArgs() },
		{ name: 'check_ssl', arguments: domainArgs() },
		{ name: 'check_mta_sts', arguments: domainArgs() },
		{ name: 'check_ns', arguments: domainArgs() },
		{ name: 'check_caa', arguments: domainArgs() },
		{ name: 'check_bimi', arguments: domainArgs() },
		{ name: 'check_tlsrpt', arguments: domainArgs() },
		{ name: 'check_http_security', arguments: domainArgs() },
		{ name: 'check_dane', arguments: domainArgs() },
		{ name: 'check_dane_https', arguments: domainArgs() },
		{ name: 'check_ptr', arguments: domainArgs() },
		{ name: 'check_svcb_https', arguments: domainArgs() },
		{ name: 'check_lookalikes', arguments: domainArgs() },
		{ name: 'check_subdomailing', arguments: domainArgs() },
		{ name: 'scan_domain', arguments: { domain: nextDomain(), profile: 'auto', force_refresh: true, format: 'full' } },
		{ name: 'batch_scan', arguments: { domains: baseDomains.slice(0, 4), force_refresh: true, format: 'compact' } },
		{ name: 'compare_domains', arguments: { domains: baseDomains.slice(1, 4), format: 'compact' } },
		{
			name: 'compare_baseline',
			arguments: { domain: nextDomain(), baseline: { grade: 'B', require_spf: true, max_high_findings: 3 }, format: 'compact' },
		},
		{ name: 'check_shadow_domains', arguments: domainArgs() },
		{ name: 'check_txt_hygiene', arguments: domainArgs() },
		{ name: 'check_mx_reputation', arguments: domainArgs() },
		{ name: 'check_srv', arguments: domainArgs() },
		{ name: 'check_zone_hygiene', arguments: domainArgs() },
		{
			name: 'generate',
			arguments: { artifact: 'dmarc_record', domain: nextDomain(), policy: 'reject', rua_email: 'dmarc@example.com', format: 'compact' },
		},
		{ name: 'get_benchmark', arguments: { profile: 'mail_enabled', format: 'compact' } },
		{ name: 'get_domain_rank', arguments: { domain: nextDomain(), score: 72, country: 'NZ', format: 'compact' } },
		{ name: 'get_provider_insights', arguments: { provider: 'cloudflare', profile: 'mail_enabled', format: 'compact' } },
		{ name: 'assess_spoofability', arguments: domainArgs() },
		{ name: 'check_resolver_consistency', arguments: { domain: nextDomain(), record_type: 'TXT', format: 'compact' } },
		{ name: 'explain_finding', arguments: { checkType: 'DMARC', status: 'high', details: 'Chaos baseline finding', format: 'compact' } },
		{ name: 'map_supply_chain', arguments: domainArgs() },
		{ name: 'analyze_drift', arguments: { domain: nextDomain(), baseline: baselineScore, format: 'compact' } },
		{ name: 'validate_fix', arguments: { domain: nextDomain(), check: 'dmarc', expected: 'v=DMARC1', format: 'compact' } },
		{ name: 'resolve_spf_chain', arguments: domainArgs() },
		{ name: 'discover_subdomains', arguments: domainArgs() },
		{ name: 'map_compliance', arguments: domainArgs() },
		{ name: 'simulate_attack_paths', arguments: domainArgs() },
		{ name: 'check_dbl', arguments: domainArgs() },
		{ name: 'check_rbl', arguments: domainArgs() },
		{ name: 'cymru_asn', arguments: domainArgs() },
		{ name: 'rdap_lookup', arguments: domainArgs() },
		{ name: 'check_nsec_walkability', arguments: domainArgs() },
		{ name: 'check_dnssec_chain', arguments: domainArgs() },
		{ name: 'check_agent_discovery', arguments: domainArgs() },
		{ name: 'check_dnskey_strength', arguments: domainArgs() },
		{ name: 'check_fast_flux', arguments: { domain: nextDomain(), rounds: 3, format: 'compact' } },
		{ name: 'check_subdomain_takeover', arguments: { domain: nextDomain(), format: 'compact' } },
		{ name: 'check_authoritative_dns_infra', arguments: domainArgs() },
		{ name: 'check_root_server_set', arguments: { format: 'compact' } },
		{
			name: 'discover_brand_domains',
			arguments: {
				domain: 'brand-example.net',
				signals: ['san', 'ns', 'dmarc_rua', 'dkim_key_reuse', 'http_redirect', 'mx_overlap', 'spf_include', 'cname_alignment'],
				candidate_domains: ['secure-example.com', 'brand-example.org'],
				dkim_selectors: ['default'],
				min_confidence: 0,
				format: 'compact',
			},
		},
		{
			name: 'discover_brand_domains_start',
			arguments: {
				domain: 'brand-example.net',
				signals: ['san', 'ns'],
				min_confidence: 0,
			},
		},
		{ name: 'discover_brand_domains_status', arguments: { operationId: 'chaos-disc-1' } },
		{ name: 'discover_brand_domains_findings', arguments: { operationId: 'chaos-disc-1' } },
		{ name: 'brand_audit_single', arguments: { domain: 'brand-example.net', format: 'json', min_confidence: 1 } },
		{
			name: 'brand_audit_batch_start',
			arguments: { domains: ['brand-example.net', 'secure.example.com'], format: 'json', min_confidence: 0.9 },
		},
		{ name: 'brand_audit_status', arguments: { auditId: 'chaos-audit-1' } },
		{ name: 'brand_audit_get_report', arguments: { auditId: 'chaos-audit-1', target: 'brand-example.net' } },
		{ name: 'list_brand_audit_watches', arguments: {} },
		{ name: 'register_brand_audit_watch', arguments: { domain: 'brand-example.net', interval: 'weekly' } },
		{ name: 'delete_brand_audit_watch', arguments: { watchId: 'chaos-watch-1' } },
		{ name: 'check_realtime_threat_feed', arguments: domainArgs() },
		{ name: 'scan_buckets_start', arguments: { target: 'example.com' } },
		{ name: 'scan_buckets_status', arguments: { scanId: 's1' } },
		{ name: 'scan_buckets_findings', arguments: {} },
		{ name: 'osint_investigate_domain_start', arguments: { query: 'example.com' } },
		{ name: 'osint_investigate_infrastructure_start', arguments: { query: 'example.com' } },
		{ name: 'osint_investigate_supply_chain_start', arguments: { query: 'example.com' } },
		{ name: 'osint_investigation_status', arguments: { investigationId: 'i1' } },
		{ name: 'osint_investigation_report', arguments: { investigationId: 'i1' } },
		{ name: 'osint_investigate_username_start', arguments: { query: 'alice' } },
		{ name: 'osint_investigate_email_start', arguments: { query: 'a@b.com' } },
		{ name: 'query_signins', arguments: { ms_tenant_id: '00000000-0000-0000-0000-000000000000' } },
		{ name: 'query_ual', arguments: { ms_tenant_id: '00000000-0000-0000-0000-000000000000' } },
		{ name: 'get_ca_policies', arguments: { ms_tenant_id: '00000000-0000-0000-0000-000000000000' } },
		{ name: 'assess_coverage', arguments: { ms_tenant_id: '00000000-0000-0000-0000-000000000000' } },
	];
}

function structuredPayload(result: ToolResult): Record<string, unknown> | null {
	const block = result.content.find((entry) => entry.type === 'text' && 'text' in entry && entry.text.includes('STRUCTURED_RESULT'));
	if (!block || !('text' in block)) return null;
	const match = block.text.match(/<!-- STRUCTURED_RESULT\n(.*)\nSTRUCTURED_RESULT -->/s);
	return match ? (JSON.parse(match[1]) as Record<string, unknown>) : null;
}

describe('chaos: varied-domain all-tools scanning', () => {
	beforeEach(() => {
		IN_MEMORY_CACHE.clear();
		installChaosFetch();
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
		IN_MEMORY_CACHE.clear();
	});

	it('keeps the all-tools chaos matrix in lockstep with the registry', () => {
		const registryNames = TOOLS.map((tool) => tool.name).sort();
		const caseNames = makeToolCases()
			.map((entry) => entry.name)
			.sort();
		expect(caseNames).toEqual(registryNames);
	});

	it('runs every registered tool through handleToolsCall without dispatcher errors', async () => {
		const runtimeOptions = {
			certstream: makeCertstreamBinding(),
			whoisBinding: makeWhoisBinding(),
			authTier: 'owner',
			principalId: 'chaos-owner',
			clientType: 'chaos_suite',
		};
		const failures: Array<{ name: string; message: string }> = [];
		const results = new Map<string, ToolResult>();

		for (const toolCase of makeToolCases()) {
			const result = await handleToolsCall(toolCase, undefined, runtimeOptions);
			results.set(toolCase.name, result);
			const text = result.content.map((entry) => ('text' in entry ? entry.text : '')).join('\n');
			if (result.isError || result.content.length === 0 || text.length === 0) {
				failures.push({
					name: toolCase.name,
					message: text.slice(0, 500) || 'empty tool response',
				});
			}
		}

		expect(failures).toEqual([]);

		const scanCase = makeToolCases().find((entry) => entry.name === 'scan_domain')!;
		const scanPayload = structuredPayload(results.get('scan_domain')!);
		expect(scanPayload?.domain).toBe(scanCase.arguments.domain);

		const statuses = scanPayload?.checkStatuses as Record<string, string>;
		const expectedScanCategories = TOOLS.filter((tool) => tool.scanIncluded).map((tool) =>
			tool.name
				.replace(/^check_/, '')
				.replace(/^cymru_asn$/, 'asn')
				.replace(/^rdap_lookup$/, 'rdap'),
		);
		for (const category of expectedScanCategories) {
			expect(statuses).toHaveProperty(category);
		}
	}, 45_000);
});
