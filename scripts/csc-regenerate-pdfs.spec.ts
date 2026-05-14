// SPDX-License-Identifier: BUSL-1.1
/**
 * scripts/regenerate-discovery-pdfs.spec.ts
 *
 * Renders Blackveil-styled discovery PDFs from the existing
 * reports/csc-audit-results.json (with 4-bucket classification including
 * `indeterminate`) without re-running discovery. Use this whenever the
 * classification logic changes or the JSON is refreshed.
 *
 * Outputs one PDF per target to ~/Desktop/{target}-discovery-report.pdf.
 */

import { describe, it } from 'vitest';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { generatePdf } from '../src/lib/pdf-engine';

const assetsDir = join(import.meta.dirname, '../assets');
const logoFullBase64 = readFileSync(join(assetsDir, 'bv-logo-full.png')).toString('base64');

interface Candidate {
	domain: string;
	registrar: string;
	source?: 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown';
	evidence: string;
	confidence: number;
	note?: string;
}

interface TargetResult {
	target: string;
	consolidated: Candidate[];
	shadowIt: Candidate[];
	indeterminate?: Candidate[];
	impersonation: Candidate[];
}

interface TargetRegistrars {
	raw: Record<string, string>;
	family: Record<string, string>;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

function renderRow(c: Candidate, badgeClass: string, signalCell: string): string {
	return `<tr>
		<td>${escapeHtml(c.domain)}${c.note ? ` <em style="color:#666;font-weight:300">(${escapeHtml(c.note)})</em>` : ''}</td>
		<td>${escapeHtml(c.registrar)}</td>
		<td><span class="badge ${badgeClass}">${escapeHtml(signalCell)}</span></td>
	</tr>`;
}

function renderEmptyRow(message: string): string {
	return `<tr><td colspan="3" style="text-align:center; color:#444">${escapeHtml(message)}</td></tr>`;
}

function buildHtml(target: string, t: TargetResult, primaryRegistrarFamily: string, dateStr: string): string {
	const indeterminate = t.indeterminate ?? [];

	const consolidatedRows = t.consolidated.length > 0
		? t.consolidated.map(c => renderRow(c, 'badge-high', c.evidence)).join('')
		: renderEmptyRow('Zero internal assets detected.');

	const shadowRows = t.shadowIt.length > 0
		? t.shadowIt.map(c => renderRow(c, 'badge-med', 'High Confidence Match')).join('')
		: renderEmptyRow('Zero Shadow IT assets detected.');

	const indeterminateRows = indeterminate.length > 0
		? indeterminate.map(c => renderRow(c, 'badge-indet', c.source ?? 'redacted')).join('')
		: renderEmptyRow('No registry-redacted candidates.');

	const impersonationRows = t.impersonation.length > 0
		? t.impersonation.map(c => renderRow(c, 'badge-low', c.evidence)).join('')
		: renderEmptyRow('Zero impersonation risks detected.');

	const ref = Buffer.from(target).toString('hex').slice(0, 8).toUpperCase();

	return `<html>
<head>
	<style>
		@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&family=JetBrains+Mono:wght@400;700&family=Manrope:wght@200;400;600&display=swap');
		body { font-family: 'Manrope', sans-serif; background-color: #000; color: #E0E0E0; line-height: 1.6; font-weight: 300; margin: 0; padding: 48px; -webkit-font-smoothing: antialiased; }
		.header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #1A1A1A; padding-bottom: 32px; margin-bottom: 48px; }
		.header-info { text-align: right; color: #888; font-size: 0.75rem; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: 0.1em; }
		.logo { height: 44px; margin-bottom: 24px; }
		h1 { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 3.5rem; margin: 0 0 8px 0; letter-spacing: -0.04em; color: #FFF; line-height: 1; }
		.subtitle { font-family: 'JetBrains Mono', monospace; color: #00FF9D; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.2em; }
		.primary { font-family: 'JetBrains Mono', monospace; color: #888; font-size: 0.75rem; margin-top: 8px; text-transform: uppercase; letter-spacing: 0.1em; }
		.section { margin-bottom: 64px; }
		h2 { font-family: 'Space Grotesk', sans-serif; font-size: 1.25rem; font-weight: 500; color: #FFF; border-bottom: 1px solid #1A1A1A; padding-bottom: 16px; margin-bottom: 32px; display: flex; align-items: center; }
		h2::before { content: ''; display: inline-block; width: 8px; height: 8px; background-color: #00FF9D; margin-right: 16px; border-radius: 1px; }
		table { width: 100%; border-collapse: separate; border-spacing: 0 8px; margin-top: -8px; }
		th { text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #666; text-transform: uppercase; letter-spacing: 0.1em; padding: 12px 24px; }
		td { background: #0A0A0A; padding: 20px 24px; font-size: 0.85rem; border-top: 1px solid #111; border-bottom: 1px solid #111; }
		td:first-child { border-left: 1px solid #111; border-radius: 4px 0 0 4px; font-weight: 600; color: #FFF; }
		td:last-child { border-right: 1px solid #111; border-radius: 0 4px 4px 0; color: #888; }
		.badge { display: inline-block; padding: 2px 8px; border-radius: 2px; font-size: 0.65rem; font-family: 'JetBrains Mono', monospace; font-weight: 700; text-transform: uppercase; }
		.badge-high { background: rgba(0, 255, 157, 0.1); color: #00FF9D; border: 1px solid rgba(0, 255, 157, 0.2); }
		.badge-med  { background: rgba(255, 204, 0, 0.1);  color: #FFCC00; border: 1px solid rgba(255, 204, 0, 0.2); }
		.badge-indet{ background: rgba(150, 150, 255, 0.1); color: #99B0FF; border: 1px solid rgba(150, 150, 255, 0.2); }
		.badge-low  { background: rgba(255, 77, 77, 0.1);  color: #FF4D4D; border: 1px solid rgba(255, 77, 77, 0.2); }
		.footer { margin-top: 120px; padding-top: 32px; border-top: 1px solid #1A1A1A; display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: #444; text-transform: uppercase; letter-spacing: 0.05em; }
	</style>
</head>
<body>
	<div class="header">
		<div>
			<img src="data:image/png;base64,${logoFullBase64}" class="logo" />
			<h1>${escapeHtml(target.toUpperCase())}</h1>
			<div class="subtitle">Discovery Intel Report</div>
			<div class="primary">Primary registrar: ${escapeHtml(primaryRegistrarFamily)}</div>
		</div>
		<div class="header-info">
			<strong>Project:</strong> Brand Portfolio Audit<br/>
			<strong>Status:</strong> External Review<br/>
			<strong>Date:</strong> ${escapeHtml(dateStr)}
		</div>
	</div>

	<div class="section">
		<h2>Consolidated Infrastructure</h2>
		<table>
			<thead><tr><th>Domain</th><th>Registrar</th><th>Signal Strength</th></tr></thead>
			<tbody>${consolidatedRows}</tbody>
		</table>
	</div>

	<div class="section">
		<h2>Shadow IT / Provider Sprawl</h2>
		<table>
			<thead><tr><th>Domain</th><th>Registrar</th><th>Risk Level</th></tr></thead>
			<tbody>${shadowRows}</tbody>
		</table>
	</div>

	<div class="section">
		<h2>Indeterminate <span style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#666;font-weight:300;margin-left:12px;text-transform:none">registry redacts registrar by policy</span></h2>
		<table>
			<thead><tr><th>Domain</th><th>Registrar</th><th>Source</th></tr></thead>
			<tbody>${indeterminateRows}</tbody>
		</table>
	</div>

	<div class="section">
		<h2>Impersonation Vectors</h2>
		<table>
			<thead><tr><th>Domain</th><th>Registrar</th><th>Signal Origin</th></tr></thead>
			<tbody>${impersonationRows}</tbody>
		</table>
	</div>

	<div class="footer">
		<div>&copy; 2026 Blackveil Security</div>
		<div>Deep Intelligence Engine v2.15.0</div>
		<div>Ref: ${ref}</div>
	</div>
</body>
</html>`;
}

describe('Regenerate discovery PDFs', () => {
	it('renders one PDF per target from current JSON without re-running discovery', async () => {
		const results: TargetResult[] = JSON.parse(readFileSync('reports/csc-audit-results.json', 'utf8'));
		const registrars: TargetRegistrars = JSON.parse(readFileSync('reports/csc-target-registrars.json', 'utf8'));
		const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

		for (const t of results) {
			const family = registrars.family[t.target] ?? 'Unknown';
			const html = buildHtml(t.target, t, family, dateStr);
			const pdfBuffer = await generatePdf(html);
			const desktopPath = join(homedir(), 'Desktop', `${t.target}-discovery-report.pdf`);
			writeFileSync(desktopPath, pdfBuffer);
			const indet = (t.indeterminate ?? []).length;
			console.log(`  ${t.target.padEnd(28)} consolidated=${t.consolidated.length} shadow=${t.shadowIt.length} indet=${indet} imp=${t.impersonation.length} → ${desktopPath}`);
		}
	}, 600_000);
});
