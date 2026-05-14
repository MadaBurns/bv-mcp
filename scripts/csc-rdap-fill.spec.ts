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

interface Candidate { domain: string; registrar: string; evidence: string; confidence: number; note?: string }
interface TargetResult { target: string; consolidated: Candidate[]; shadowIt: Candidate[]; impersonation: Candidate[] }

async function lookupRegistrar(domain: string): Promise<string> {
	try {
		const rdap = await checkRdapLookup(domain, { whoisBinding: LIVE_WHOIS_BINDING });
		const rFind = rdap.findings.find(
			f => typeof f.metadata?.registrar === 'string' && (f.metadata.registrar as string).length > 0,
		);
		return rFind ? (rFind.metadata!.registrar as string) : 'Unknown';
	} catch {
		return 'Unknown';
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
			const raw = await lookupRegistrar(target);
			targetRegistrarRaw[target] = raw;
			targetRegistrarFamily[target] = normalizeRegistrar(raw);
			console.log(`  ${target.padEnd(28)} ${targetRegistrarFamily[target].padEnd(20)} (${raw})`);
		}

		// Dedupe candidate domains across all buckets
		const uniqueCandidates = new Set<string>();
		for (const t of existing) {
			for (const bucket of [t.consolidated, t.shadowIt, t.impersonation]) {
				for (const c of bucket) uniqueCandidates.add(c.domain);
			}
		}
		console.log(`\n=== Re-RDAPing ${uniqueCandidates.size} unique candidates ===`);

		const registrarCache = new Map<string, string>();
		for (const domain of uniqueCandidates) {
			registrarCache.set(domain, await lookupRegistrar(domain));
		}

		// Re-classify: same-family-as-target = consolidated; conf≥0.7 + different family = shadowIt; else impersonation
		const fixed: TargetResult[] = existing.map(t => {
			const targetFamily = targetRegistrarFamily[t.target];
			const allCandidates = [...t.consolidated, ...t.shadowIt, ...t.impersonation];
			const newConsolidated: Candidate[] = [];
			const newShadowIt: Candidate[] = [];
			const newImpersonation: Candidate[] = [];

			for (const c of allCandidates) {
				const registrarRaw = registrarCache.get(c.domain) ?? 'Unknown';
				const candFamily = normalizeRegistrar(registrarRaw);
				const enriched: Candidate = { ...c, registrar: registrarRaw };

				// Same registrar family as target (and not Unknown==Unknown coincidence) → consolidated
				if (candFamily !== 'Unknown' && targetFamily !== 'Unknown' && candFamily === targetFamily) {
					newConsolidated.push(enriched);
				} else if (isSubdomainOf(c.domain, t.target)) {
					newConsolidated.push({ ...enriched, note: 'Organizational Subdomain' });
				} else if (c.confidence >= 0.7) {
					// High-confidence brand signal on a different/unknown registrar = provider sprawl / shadow IT
					newShadowIt.push(enriched);
				} else {
					newImpersonation.push(enriched);
				}
			}

			return { target: t.target, consolidated: newConsolidated, shadowIt: newShadowIt, impersonation: newImpersonation };
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
				`  ${t.target.padEnd(28)} [${family.padEnd(14)}] consolidated=${t.consolidated.length} shadow=${t.shadowIt.length} imp=${t.impersonation.length}`,
			);
		}
	}, 1_800_000);
});
