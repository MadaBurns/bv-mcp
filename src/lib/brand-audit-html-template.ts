// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure HTML template for brand-audit PDF reports.
 *
 * Extracted from the inline template in `scripts/brand-audit-brand-audit.spec.ts` so it
 * can be invoked from a Cloudflare Worker (no Node.js Buffer dependency, no
 * filesystem reads). Worker-runtime safe — only string operations.
 *
 * Output is intended for Cloudflare Browser Rendering via `BV_BROWSER_RENDERER`
 * (see `src/lib/brand-audit-pdf.ts`). The styling deliberately uses dark
 * Blackveil palette + Google Fonts; the renderer Worker fetches the fonts at
 * render time.
 *
 * One observable behavior: same input always produces same output. No clock,
 * no random IDs — date is an injected parameter so tests can lock it.
 */

import type { CheckResult } from './scoring';

export type BrandAuditBucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation';
export type BrandRelationshipType =
	| 'owned_primary'
	| 'owned_off_primary_registrar'
	| 'authorized_vendor_dependency'
	| 'manual_review'
	| 'impersonation_risk'
	| 'impersonation_surface';

export interface BrandCandidateRow {
	domain: string;
	bucket: BrandAuditBucket;
	relationshipType: BrandRelationshipType;
	registrar: string;
	registrarSource: string;
	reasons: string[];
	signals: string[];
	combinedConfidence: number;
	/** True when the heuristic in `brand-defensive-registration.ts` flagged this candidate. */
	defensive?: boolean;
	/** Discriminated reason token from the same heuristic. */
	defensiveReason?: 'redirect-to-target' | 'no-mx' | 'parked-ns';
}

function relationshipTypeFor(bucket: BrandAuditBucket, raw: unknown): BrandRelationshipType {
	if (raw === 'owned_primary' || raw === 'owned_off_primary_registrar' || raw === 'authorized_vendor_dependency' || raw === 'manual_review' || raw === 'impersonation_risk' || raw === 'impersonation_surface') {
		return raw;
	}
	if (bucket === 'shadowIt') return 'owned_off_primary_registrar';
	if (bucket === 'consolidated') return 'owned_primary';
	if (bucket === 'impersonation') return 'impersonation_risk';
	return 'manual_review';
}

export interface BrandAuditHtmlInput {
	target: string;
	dateIso: string;
	serverVersion: string;
	candidates: BrandCandidateRow[];
	/** Optional inline base64 PNG/SVG. Omit for an unbranded report. */
	logoBase64?: string;
	logoMimeType?: 'image/png' | 'image/svg+xml';
	/**
	 * Buckets whose classifier branch actually fired during this audit. Used by
	 * the template to distinguish empty-because-nothing-matched from
	 * empty-because-not-run. Omitting it preserves prior behavior — every empty
	 * bucket is treated as `empty-verified` (back-compat).
	 */
	bucketsExercised?: ReadonlySet<BrandAuditBucket>;
}

/**
 * Sanitize untrusted text for safe interpolation into HTML. Strips/escapes the
 * five XML reserved characters. Used for every `${...}` insertion except where
 * the value is hex/ASCII-only by construction.
 */
function esc(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/** Hex digest of an ASCII string. Worker-safe (no Buffer). 8 chars uppercase. */
function shortRefHex(input: string): string {
	let hash = 5381;
	for (let i = 0; i < input.length; i++) {
		hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
	}
	return ((hash >>> 0).toString(16).padStart(8, '0')).slice(0, 8).toUpperCase();
}

/** Extract one row per candidate from a `brand_audit_single` CheckResult. */
export function candidatesFromCheckResult(result: CheckResult): BrandCandidateRow[] {
	const rows: BrandCandidateRow[] = [];
	for (const f of result.findings) {
		const m = f.metadata;
		if (!m || typeof m.candidate !== 'string' || typeof m.bucket !== 'string') continue;
		const bucket = m.bucket as BrandAuditBucket;
		const defensiveReason =
			m.defensiveReason === 'redirect-to-target' || m.defensiveReason === 'no-mx' || m.defensiveReason === 'parked-ns'
				? m.defensiveReason
				: undefined;
		rows.push({
			domain: m.candidate as string,
			bucket,
			relationshipType: relationshipTypeFor(bucket, m.relationshipType),
			registrar: typeof m.registrar === 'string' ? m.registrar : 'Unknown',
			registrarSource: typeof m.registrarSource === 'string' ? m.registrarSource : 'unknown',
			reasons: Array.isArray(m.reasons) ? (m.reasons as string[]) : [],
			signals: Array.isArray(m.signals) ? (m.signals as string[]) : [],
			combinedConfidence: typeof m.combinedConfidence === 'number' ? (m.combinedConfidence as number) : 0,
			...(m.defensive === true ? { defensive: true } : {}),
			...(defensiveReason ? { defensiveReason } : {}),
		});
	}
	return rows;
}

/**
 * Build third-party verification links per candidate. Each signal in
 * `r.signals` maps to one or more public, auditable sources a reviewer can
 * re-run by hand to confirm the claim. Domain-level links (crt.sh, RDAP)
 * always render so reviewers have a baseline to spot-check from. Signal
 * names match `src/tools/brand-audit-single.ts` classification output —
 * keep this map in sync.
 */
function citationLinks(r: BrandCandidateRow): string {
	const domain = encodeURIComponent(r.domain);
	const items: Array<{ href: string; label: string }> = [];
	items.push({ href: `https://crt.sh/?q=${domain}`, label: 'crt.sh' });
	items.push({ href: `https://rdap.org/domain/${domain}`, label: 'rdap' });

	const seen = new Set<string>();
	for (const s of r.signals) {
		const key = s.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);

		if (key.includes('san') || key.includes('cert')) {
			items.push({ href: `https://crt.sh/?q=${domain}&exclude=expired`, label: 'cert' });
		} else if (key.startsWith('ns_') || key === 'ns_overlap' || key === 'ns_match') {
			items.push({ href: `https://dns.google/resolve?name=${domain}&type=NS`, label: 'ns' });
		} else if (key.includes('dkim')) {
			items.push({ href: `https://dns.google/resolve?name=default._domainkey.${domain}&type=TXT`, label: 'dkim' });
		} else if (key.includes('dmarc')) {
			items.push({ href: `https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`, label: 'dmarc' });
		} else if (key.includes('spf') || key.includes('txt')) {
			items.push({ href: `https://dns.google/resolve?name=${domain}&type=TXT`, label: 'spf' });
		} else if (key.startsWith('mx_') || key.includes('mail')) {
			items.push({ href: `https://dns.google/resolve?name=${domain}&type=MX`, label: 'mx' });
		} else if (key.includes('caa')) {
			items.push({ href: `https://dns.google/resolve?name=${domain}&type=CAA`, label: 'caa' });
		} else if (key.includes('registrar') || key.includes('rdap') || key.includes('whois')) {
			items.push({ href: `https://rdap.org/domain/${domain}`, label: 'whois' });
		}
	}

	return items
		.map((it) => `<a class="cite" href="${esc(it.href)}" target="_blank" rel="noopener">${esc(it.label)}</a>`)
		.join(' ');
}

function renderTableSection(
	title: string,
	bucket: BrandAuditBucket,
	rows: BrandCandidateRow[],
	emptyMessage: string,
	badgeClass: string,
	columnLabel: string,
	columnValue: (r: BrandCandidateRow) => string,
	emptyState: 'empty-verified' | 'not-run' | null,
): string {
	const body = rows.length === 0
		? `<tr><td colspan="4" style="text-align:center; color:#444">${esc(emptyMessage)}</td></tr>`
		: rows.map((r) => {
			const sourceBadge = r.registrarSource === 'redacted' || r.registrarSource === 'notfound'
				? ` <span class="badge badge-gray">${esc(r.registrarSource)}</span>`
				: '';
			// Defensive-registration label — see `brand-defensive-registration.ts`. The
			// candidate stays in its classifier-assigned bucket; the badge tells the
			// reader this is a deliberately-parked typo defence, not operational infra.
			const defensiveBadge = r.defensive
				? ` <span class="badge badge-gray" title="${esc(`defensive registration${r.defensiveReason ? ` — ${r.defensiveReason}` : ''}`)}">defensive</span>`
				: '';
			return `<tr>
				<td>${esc(r.domain)}${defensiveBadge}</td>
				<td>${esc(r.registrar)}${sourceBadge}</td>
				<td><span class="badge ${badgeClass}">${esc(columnValue(r))}</span></td>
				<td class="sources">${citationLinks(r)}</td>
			</tr>`;
		}).join('');

	// `data-bucket` always emitted (machine-readable bucket identity); `data-state`
	// emitted only for empty buckets so reviewers can tell apart "checked, nothing
	// found" (empty-verified) from "code path didn't fire" (not-run).
	const stateAttr = rows.length === 0 && emptyState ? ` data-state="${emptyState}"` : '';

	return `<div class="section">
		<h2>${esc(title)}</h2>
		<table data-bucket="${bucket}"${stateAttr}>
			<thead><tr><th>Domain</th><th>Registrar</th><th>${esc(columnLabel)}</th><th>Sources</th></tr></thead>
			<tbody>${body}</tbody>
		</table>
	</div>`;
}

/** Render the full brand-audit PDF HTML. Pure: same inputs always produce same output. */
export function renderBrandAuditHtml(input: BrandAuditHtmlInput): string {
	const target = input.target.trim().toLowerCase();
	const dateLabel = new Date(input.dateIso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
	const refHex = shortRefHex(target);
	const by: Record<BrandAuditBucket, BrandCandidateRow[]> = { consolidated: [], shadowIt: [], indeterminate: [], impersonation: [] };
	for (const c of input.candidates) {
		by[c.bucket]?.push(c);
	}

	const logoTag = input.logoBase64 && input.logoMimeType
		? `<img src="data:${input.logoMimeType};base64,${input.logoBase64}" class="logo" alt="Blackveil" />`
		: '';

	const reasonOrInsufficient = (r: BrandCandidateRow): string => r.reasons[0] ?? 'insufficient evidence';
	const signalSummary = (r: BrandCandidateRow): string => {
		if (r.signals.length === 0) return `${r.combinedConfidence.toFixed(2)}`;
		return `${r.signals.slice(0, 2).join(', ')} · ${r.combinedConfidence.toFixed(2)}`;
	};

	// Back-compat: when `bucketsExercised` is omitted, every empty bucket is
	// treated as `empty-verified` (matches the pre-transparency behavior of
	// "we always assumed we ran the classifier"). When it's provided,
	// membership decides — missing => `not-run`.
	const stateFor = (bucket: BrandAuditBucket): 'empty-verified' | 'not-run' => {
		if (!input.bucketsExercised) return 'empty-verified';
		return input.bucketsExercised.has(bucket) ? 'empty-verified' : 'not-run';
	};

	return `<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Brand Audit — ${esc(target)}</title>
<style>
/* No external @import: Google Fonts hang the renderer's waitUntil networkidle0
   past the 30s safeFetch budget, 504-timing-out every /pdf/html request
   (verified 2026-05-19 against multiple audits). System font stack instead. */
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background-color: #000000; color: #E0E0E0; line-height: 1.6; font-weight: 300; margin: 0; padding: 48px; -webkit-font-smoothing: antialiased; }
.header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #1A1A1A; padding-bottom: 32px; margin-bottom: 48px; }
.header-info { text-align: right; color: #888888; font-size: 0.75rem; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; text-transform: uppercase; letter-spacing: 0.1em; }
.logo { height: 44px; margin-bottom: 24px; }
h1 { font-weight: 700; font-size: 3.5rem; margin: 0 0 8px 0; letter-spacing: -0.04em; color: #FFFFFF; line-height: 1; }
.subtitle { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; color: #00FF9D; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.2em; }
.section { margin-bottom: 64px; }
h2 { font-size: 1.25rem; font-weight: 500; color: #FFFFFF; border-bottom: 1px solid #1A1A1A; padding-bottom: 16px; margin-bottom: 32px; display: flex; align-items: center; }
h2::before { content: ''; display: inline-block; width: 8px; height: 8px; background-color: #00FF9D; margin-right: 16px; border-radius: 1px; }
table { width: 100%; border-collapse: separate; border-spacing: 0 8px; margin-top: -8px; }
th { text-align: left; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: 0.7rem; color: #666666; text-transform: uppercase; letter-spacing: 0.1em; padding: 12px 24px; }
td { background: #0A0A0A; padding: 20px 24px; font-size: 0.85rem; border-top: 1px solid #111111; border-bottom: 1px solid #111111; }
td:first-child { border-left: 1px solid #111111; border-radius: 4px 0 0 4px; font-weight: 600; color: #FFFFFF; }
td:last-child { border-right: 1px solid #111111; border-radius: 0 4px 4px 0; color: #888888; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 2px; font-size: 0.65rem; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-weight: 700; text-transform: uppercase; }
.badge-high { background: rgba(0, 255, 157, 0.1); color: #00FF9D; border: 1px solid rgba(0, 255, 157, 0.2); }
.badge-med { background: rgba(255, 204, 0, 0.1); color: #FFCC00; border: 1px solid rgba(255, 204, 0, 0.2); }
.badge-low { background: rgba(255, 77, 77, 0.1); color: #FF4D4D; border: 1px solid rgba(255, 77, 77, 0.2); }
.badge-gray { background: rgba(180, 180, 180, 0.06); color: #999999; border: 1px solid rgba(180, 180, 180, 0.18); }
.sources { font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: 0.65rem; }
.cite { display: inline-block; margin-right: 6px; padding: 2px 6px; border-radius: 2px; color: #00FF9D; background: rgba(0, 255, 157, 0.05); border: 1px solid rgba(0, 255, 157, 0.15); text-decoration: none; text-transform: uppercase; letter-spacing: 0.05em; }
.footer { margin-top: 120px; padding-top: 32px; border-top: 1px solid #1A1A1A; display: flex; justify-content: space-between; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; font-size: 0.65rem; color: #444444; text-transform: uppercase; letter-spacing: 0.05em; }
</style></head><body>
<div class="header">
<div>${logoTag}<h1>${esc(target.toUpperCase())}</h1><div class="subtitle">Discovery Intel Report</div></div>
<div class="header-info"><strong>Project:</strong> Brand Audit<br/><strong>Status:</strong> Automated<br/><strong>Date:</strong> ${esc(dateLabel)}</div>
</div>
${renderTableSection('Consolidated Infrastructure', 'consolidated', by.consolidated, 'Zero internal assets detected.', 'badge-high', 'Signal Strength', signalSummary, stateFor('consolidated'))}
${renderTableSection('Registrar Sprawl / Real Shadow IT', 'shadowIt', by.shadowIt, 'Zero off-primary owned domains detected.', 'badge-med', 'Risk Level', () => 'Owned Off-Registrar', stateFor('shadowIt'))}
${renderTableSection('Indeterminate', 'indeterminate', by.indeterminate, 'Zero indeterminate candidates.', 'badge-gray', 'Reason', reasonOrInsufficient, stateFor('indeterminate'))}
${renderTableSection('Impersonation Vectors', 'impersonation', by.impersonation, 'Zero impersonation risks detected.', 'badge-low', 'Signal Origin', signalSummary, stateFor('impersonation'))}
<div class="footer"><div>&copy; ${new Date(input.dateIso).getFullYear()} Blackveil Security</div><div>Deep Intelligence Engine v${esc(input.serverVersion)}</div><div>Ref: ${refHex}</div></div>
</body></html>`;
}
