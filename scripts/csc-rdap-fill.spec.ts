// SPDX-License-Identifier: BUSL-1.1
/**
 * scripts/csc-rdap-fill.spec.ts
 *
 * Re-fills the `registrar` field for every candidate in reports/csc-audit-results.json
 * via checkRdapLookup, then re-classifies using the target's own registrar as the
 * consolidation baseline (not hardcoded CSC). Normalizes registrar strings so MarkMonitor /
 * Com Laude / SafeNames variants collapse to one family per provider.
 *
 * Buckets:
 *  - consolidated: same normalized registrar as the target (org-controlled, central)
 *  - shadowIt:     high-confidence candidate on a DIFFERENT or Unknown registrar (provider sprawl / shadow IT)
 *  - impersonation: low-confidence candidate (likely adversary or generated noise)
 */

import { describe, it } from 'vitest';
import { readFileSync, writeFileSync } from 'fs';
import { checkRdapLookup } from '../src/tools/check-rdap-lookup';

/**
 * Production-shaped Fetcher that targets the live bv-whois shim Worker. This is
 * what the `BV_WHOIS` service binding does at runtime; in node env we just hit
 * the public URL so the audit exercises the same end-to-end fallback path.
 */
const LIVE_WHOIS_BINDING: { fetch: typeof fetch } = {
	async fetch(input: RequestInfo, init?: RequestInit) {
		// Rewrite the "internal" hostname (https://bv-whois/lookup) to the live shim.
		const req = typeof input === 'string' ? new Request(input, init) : input;
		const path = new URL(req.url).pathname;
		const target = `https://bv-whois.bv-edge.workers.dev${path}`;
		return fetch(target, {
			method: req.method,
			headers: req.headers,
			body: req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.clone().text(),
		});
	},
};

const TARGETS = [
	'google.com', 'amazon.com', 'microsoft.com', 'apple.com', 'disney.com',
	'nike.com', 'paypal.com', 'stripe.com', 'walmart.com', 'github.com',
	'blackveilsecurity.com',
];

function normalizeRegistrar(raw: string): string {
	if (!raw || raw === 'Unknown') return 'Unknown';
	const lower = raw.toLowerCase();
	if (/markmonitor/.test(lower)) return 'MarkMonitor';
	if (/com\s*laude|nom[ -]?iq/.test(lower)) return 'Com Laude';
	if (/safenames/.test(lower)) return 'SafeNames';
	if (/csc\s*corporate|csc\s*global|corporate domains/.test(lower)) return 'CSC';
	if (/cloudflare/.test(lower)) return 'Cloudflare';
	if (/tucows/.test(lower)) return 'Tucows';
	if (/godaddy/.test(lower)) return 'GoDaddy';
	if (/namecheap/.test(lower)) return 'Namecheap';
	if (/network solutions|networksolutions/.test(lower)) return 'Network Solutions';
	if (/gandi/.test(lower)) return 'Gandi';
	return raw.trim();
}

function isSubdomainOf(cand: string, target: string) {
	return cand === target || cand.endsWith('.' + target);
}

type RegistrarSource = 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown';

interface Candidate { domain: string; registrar: string; source?: RegistrarSource; evidence: string; confidence: number; note?: string }
interface TargetResult {
	target: string;
	consolidated: Candidate[];
	shadowIt: Candidate[];
	/** Registry refuses to disclose registrar (e.g. DENIC by German law). Genuinely
	 *  unknowable from WHOIS — separate signal from "we couldn't reach the server". */
	indeterminate: Candidate[];
	impersonation: Candidate[];
}

interface LookupResult { registrar: string; source: RegistrarSource }

/**
 * Look up the registrar AND its provenance. The source field discriminates:
 *   - 'rdap' / 'whois' = we have a real registrar string
 *   - 'redacted' = registry exists but won't tell us (e.g. DENIC)
 *   - 'notfound' = registry says domain doesn't exist
 *   - 'unknown' = we couldn't reach the registry or shim failed
 */
async function lookupRegistrar(domain: string): Promise<LookupResult> {
	try {
		const rdap = await checkRdapLookup(domain, { whoisBinding: LIVE_WHOIS_BINDING });
		// Prefer findings that carry registrarSource metadata (set by the WHOIS fallback path).
		const find = rdap.findings.find(f => f.metadata?.registrarSource) ?? rdap.findings.find(f => f.metadata?.registrar);
		const source = (find?.metadata?.registrarSource as RegistrarSource | undefined) ?? 'unknown';
		const registrar = typeof find?.metadata?.registrar === 'string' && (find.metadata.registrar as string).length > 0
			? (find.metadata.registrar as string)
			: 'Unknown';
		return { registrar, source };
	} catch {
		return { registrar: 'Unknown', source: 'unknown' };
	}
}

describe('CSC RDAP fill', () => {
	it('refreshes registrar data and re-classifies', async () => {
		const existing: TargetResult[] = JSON.parse(readFileSync('reports/csc-audit-results.json', 'utf8'));

		// Look up the 11 target registrars — these become the per-target consolidation baseline
		console.log('\n=== Target registrar verification ===');
		const targetRegistrarRaw: Record<string, string> = {};
		const targetRegistrarFamily: Record<string, string> = {};
		for (const target of TARGETS) {
			const { registrar: raw } = await lookupRegistrar(target);
			targetRegistrarRaw[target] = raw;
			targetRegistrarFamily[target] = normalizeRegistrar(raw);
			console.log(`  ${target.padEnd(28)} ${targetRegistrarFamily[target].padEnd(20)} (${raw})`);
		}

		// Dedupe candidate domains across all buckets — includes new `indeterminate` bucket if present.
		const uniqueCandidates = new Set<string>();
		for (const t of existing) {
			for (const bucket of [t.consolidated, t.shadowIt, t.indeterminate ?? [], t.impersonation]) {
				for (const c of bucket) uniqueCandidates.add(c.domain);
			}
		}
		console.log(`\n=== Re-RDAPing ${uniqueCandidates.size} unique candidates ===`);

		const lookupCache = new Map<string, LookupResult>();
		for (const domain of uniqueCandidates) {
			lookupCache.set(domain, await lookupRegistrar(domain));
		}

		// Re-classify:
		//   - source=redacted → indeterminate (registry hides the answer by policy; e.g. DENIC)
		//   - same-family-as-target → consolidated
		//   - subdomain of target → consolidated (org subdomain)
		//   - confidence ≥ 0.7 + different family → shadow IT / sprawl
		//   - else → impersonation
		const fixed: TargetResult[] = existing.map(t => {
			const targetFamily = targetRegistrarFamily[t.target];
			const allCandidates = [
				...t.consolidated,
				...t.shadowIt,
				...(t.indeterminate ?? []),
				...t.impersonation,
			];
			const newConsolidated: Candidate[] = [];
			const newShadowIt: Candidate[] = [];
			const newIndeterminate: Candidate[] = [];
			const newImpersonation: Candidate[] = [];

			for (const c of allCandidates) {
				const lookup = lookupCache.get(c.domain) ?? { registrar: 'Unknown', source: 'unknown' as const };
				const candFamily = normalizeRegistrar(lookup.registrar);
				const enriched: Candidate = { ...c, registrar: lookup.registrar, source: lookup.source };

				// Registry refuses to disclose by policy — separate from "we couldn't find out".
				if (lookup.source === 'redacted') {
					newIndeterminate.push(enriched);
				} else if (candFamily !== 'Unknown' && targetFamily !== 'Unknown' && candFamily === targetFamily) {
					newConsolidated.push(enriched);
				} else if (isSubdomainOf(c.domain, t.target)) {
					newConsolidated.push({ ...enriched, note: 'Organizational Subdomain' });
				} else if (c.confidence >= 0.7) {
					newShadowIt.push(enriched);
				} else {
					newImpersonation.push(enriched);
				}
			}

			return {
				target: t.target,
				consolidated: newConsolidated,
				shadowIt: newShadowIt,
				indeterminate: newIndeterminate,
				impersonation: newImpersonation,
			};
		});

		writeFileSync('reports/csc-audit-results.json', JSON.stringify(fixed, null, 2));
		writeFileSync(
			'reports/csc-target-registrars.json',
			JSON.stringify({ raw: targetRegistrarRaw, family: targetRegistrarFamily }, null, 2),
		);

		console.log('\n=== Summary (re-classified) ===');
		for (const t of fixed) {
			const family = targetRegistrarFamily[t.target];
			console.log(
				`  ${t.target.padEnd(28)} [${family.padEnd(14)}] consolidated=${t.consolidated.length} shadow=${t.shadowIt.length} indet=${t.indeterminate.length} imp=${t.impersonation.length}`,
			);
		}
	}, 1_800_000);
});
