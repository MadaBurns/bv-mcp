#!/usr/bin/env node
// Generate reports/CONSOLIDATED_BRAND_AUDIT.md from the corrected JSON.
// Pure read-from-JSON — no network calls.

import { readFileSync, writeFileSync } from 'fs';

const results = JSON.parse(readFileSync('reports/brand-audit-audit-results.json', 'utf8'));
const targetRegs = JSON.parse(readFileSync('reports/brand-audit-target-registrars.json', 'utf8'));
const dateStr = new Date().toISOString().split('T')[0];

const lines = [];
lines.push('# Brand Audit: Shadow IT & Provider Sprawl');
lines.push('');
lines.push(`**Generated:** ${dateStr}  `);
lines.push('**Scope:** 11 targets, lookalike TLD variants discovered via SAN / NS / DMARC RUA / DKIM key reuse signals  ');
lines.push('**Classification:** same-registrar-family-as-target = consolidated; different registrar + high confidence = shadow IT / sprawl; registry refuses to disclose (e.g. DENIC) = indeterminate; low confidence = impersonation.');
lines.push('');

// Aggregate sprawl: how many distinct registrar families exist across each target's domains
lines.push('## Headline');
lines.push('');
let totalConsolidated = 0, totalShadow = 0, totalIndet = 0, totalImp = 0;
const sprawlPerTarget = {};
for (const t of results) {
	const indet = t.indeterminate ?? [];
	totalConsolidated += t.consolidated.length;
	totalShadow += t.shadowIt.length;
	totalIndet += indet.length;
	totalImp += t.impersonation.length;
	const families = new Set();
	families.add(targetRegs.family[t.target]);
	for (const c of [...t.shadowIt, ...t.impersonation]) {
		const reg = (c.registrar || 'Unknown').toLowerCase();
		if (/markmonitor/.test(reg)) families.add('MarkMonitor');
		else if (/com\s*laude|nom[ -]?iq/.test(reg)) families.add('Com Laude');
		else if (/safenames/.test(reg)) families.add('SafeNames');
		else if (/brand-audit\s*corporate|brand-audit\s*global|corporate domains/.test(reg)) families.add('BrandAudit');
		else if (/cloudflare/.test(reg)) families.add('Cloudflare');
		else if (/tucows/.test(reg)) families.add('Tucows');
		else if (reg === 'unknown') families.add('Unknown');
		else families.add(c.registrar);
	}
	sprawlPerTarget[t.target] = families;
}
lines.push(`- **${totalConsolidated}** consolidated (same registrar as target, centrally managed)`);
lines.push(`- **${totalShadow}** shadow IT / provider sprawl (high-confidence brand signal on a different registrar)`);
lines.push(`- **${totalIndet}** indeterminate (registry redacts registrar by policy — e.g. DENIC)`);
lines.push(`- **${totalImp}** likely impersonation / low-confidence noise`);
lines.push('');
lines.push('### Premise check: how many targets actually use BrandAudit?');
lines.push('');
lines.push('| Target | Registrar family | On BrandAudit? |');
lines.push('|---|---|:---:|');
for (const target of Object.keys(targetRegs.family)) {
	const fam = targetRegs.family[target];
	const onBrandAudit = fam === 'BrandAudit' ? '✓' : '—';
	lines.push(`| ${target} | ${fam} (${targetRegs.raw[target]}) | ${onBrandAudit} |`);
}
lines.push('');
lines.push('> **Only 2 of 11 are BrandAudit-managed (Disney, Walmart).** The original audit premise treated all 11 as BrandAudit; six are actually on MarkMonitor, Apple on Com Laude, Stripe on SafeNames, Blackveil on Cloudflare.');
lines.push('');

// Per-target detail
lines.push('## Per-target detail');
lines.push('');
for (const t of results) {
	const family = targetRegs.family[t.target];
	const sprawlCount = sprawlPerTarget[t.target].size;
	lines.push(`### ${t.target} — primary: ${family} (${sprawlCount} registrar families across portfolio)`);
	lines.push('');

	if (t.consolidated.length > 0) {
		lines.push('**Consolidated** (same registrar family as target):');
		lines.push('');
		lines.push('| Domain | Registrar | Evidence | Confidence |');
		lines.push('|---|---|---|---:|');
		for (const c of t.consolidated) {
			lines.push(`| \`${c.domain}\`${c.note ? ` *(${c.note})*` : ''} | ${c.registrar} | ${c.evidence} | ${c.confidence} |`);
		}
		lines.push('');
	}

	if (t.shadowIt.length > 0) {
		lines.push('**Shadow IT / Provider Sprawl** (high-confidence, different registrar):');
		lines.push('');
		lines.push('| Domain | Registrar | Evidence | Confidence |');
		lines.push('|---|---|---|---:|');
		for (const c of t.shadowIt) {
			lines.push(`| \`${c.domain}\` | ${c.registrar} | ${c.evidence} | ${c.confidence} |`);
		}
		lines.push('');
	}

	const indet = t.indeterminate ?? [];
	if (indet.length > 0) {
		lines.push('**Indeterminate** (registry refuses to disclose registrar — registrar may still be the same family):');
		lines.push('');
		lines.push('| Domain | Source | Evidence | Confidence |');
		lines.push('|---|---|---|---:|');
		for (const c of indet) {
			lines.push(`| \`${c.domain}\` | ${c.source ?? 'redacted'} | ${c.evidence} | ${c.confidence} |`);
		}
		lines.push('');
	}

	if (t.impersonation.length > 0) {
		lines.push('**Impersonation / Low Confidence**:');
		lines.push('');
		lines.push('| Domain | Registrar | Evidence | Confidence |');
		lines.push('|---|---|---|---:|');
		for (const c of t.impersonation) {
			lines.push(`| \`${c.domain}\` | ${c.registrar} | ${c.evidence} | ${c.confidence} |`);
		}
		lines.push('');
	}

	if (t.consolidated.length === 0 && t.shadowIt.length === 0 && indet.length === 0 && t.impersonation.length === 0) {
		lines.push('_No candidate domains surfaced by discovery signals._');
		lines.push('');
	}
}

// Cross-target registrar tally
lines.push('## Cross-portfolio registrar distribution');
lines.push('');
lines.push('Across all 44 candidate domains:');
lines.push('');
const tally = {};
for (const t of results) {
	for (const c of [...t.consolidated, ...t.shadowIt, ...(t.indeterminate ?? []), ...t.impersonation]) {
		const reg = c.registrar || 'Unknown';
		tally[reg] = (tally[reg] || 0) + 1;
	}
}
const sorted = Object.entries(tally).sort((a, b) => b[1] - a[1]);
lines.push('| Registrar | Candidates |');
lines.push('|---|---:|');
for (const [reg, count] of sorted) {
	lines.push(`| ${reg} | ${count} |`);
}
lines.push('');

lines.push('## Methodology notes & caveats');
lines.push('');
lines.push('- **ccTLDs without RDAP** (`.me/.co/.us/.sh/.io/.uk/.fr/.ca/...`) resolved via the bv-whois shim Worker (WHOIS-over-TCP/43 with IANA referral cache).');
lines.push('- **`.de` (DENIC) is short-circuited as redacted** — German law (BDSG) requires the registry to withhold the registrar field, and DENIC blocks Cloudflare Workers\' egress IPs at port 43. The shim returns `source: redacted` instantly without contacting the network.');
lines.push('- **MarkMonitor / Com Laude / SafeNames** each appear under multiple string variants (case, regional subsidiary, dba); normalized to one family per provider.');
lines.push('- **Confidence threshold for shadow IT = 0.7** matches the original spec. Defensive registrations at conf=0.5 (e.g., `brand-name.app/io/org`) fall into the impersonation bucket despite being likely brand-owned. Threshold tuning is a follow-up.');
lines.push('- **Candidate set is `<base>.<TLD>` for 15 hardcoded TLDs.** Subdomains under target (e.g., `mail.apple.com`) come from discovery signals separately.');

writeFileSync('reports/CONSOLIDATED_BRAND_AUDIT.md', lines.join('\n'));
console.log(`Wrote reports/CONSOLIDATED_BRAND_AUDIT.md (${lines.length} lines)`);
