// SPDX-License-Identifier: BUSL-1.1
/**
 * Cross-repo scoring parity — bv-mcp side.
 *
 * Runs the REAL checkDMARC (full fact-extraction + classifier) over each corpus
 * fixture's records and asserts the canonical score + missingControl. bv-web runs
 * the SAME corpus through its own full check; with the version-lock, agreement is
 * transitive (bv-web == corpus == bv-mcp). `treeWalkOnly` fixtures are skipped
 * here — bv-mcp does not tree-walk (documented bounded-non-parity).
 *
 * Design: bv-web docs/superpowers/specs/2026-05-31-cross-repo-scoring-parity-gate-design.md
 */
import { describe, it, expect } from 'vitest';
import { checkDMARC, checkDANEHTTPS, checkSVCBHTTPS } from '../checks';
import { scoreIndicatesMissingControl } from '../scoring';
import pkg from '../../package.json';
import {
	DMARC_PARITY_FIXTURES,
	DANE_HTTPS_PARITY_FIXTURES,
	SVCB_HTTPS_PARITY_FIXTURES,
	PARITY_CORPUS_VERSION,
} from '../parity-fixtures';

function missingControl(findings: Parameters<typeof scoreIndicatesMissingControl>[0]): boolean {
	return (
		scoreIndicatesMissingControl(findings) ||
		findings.some((f) => f.metadata?.missingControl === true)
	);
}

describe('DMARC parity corpus — bv-mcp full checkDMARC', () => {
	it('version-lock: package version === corpus version', () => {
		expect(pkg.version).toBe(PARITY_CORPUS_VERSION);
	});

	// bv-mcp now does the RFC 9989 §4.10 tree walk, so it asserts ALL DMARC
	// fixtures including the inheriting-subdomain case (formerly treeWalkOnly).
	for (const fx of DMARC_PARITY_FIXTURES) {
		it(`scores "${fx.name}" → ${fx.expectedScore} (missingControl=${fx.expectedMissingControl})`, async () => {
			const queryDNS = (async (name: string) => fx.records[name] ?? []) as never;
			const domain = fx.query.replace(/^_dmarc\./, '');
			const result = await checkDMARC(domain, queryDNS);
			expect({ score: result.score, missing: missingControl(result.findings) }).toEqual({
				score: fx.expectedScore,
				missing: fx.expectedMissingControl,
			});
		});
	}
});

describe('DANE-HTTPS parity corpus — bv-mcp full checkDANEHTTPS', () => {
	for (const fx of DANE_HTTPS_PARITY_FIXTURES) {
		it(`scores "${fx.name}" → ${fx.expectedScore} (missingControl=${fx.expectedMissingControl})`, async () => {
			const queryDNS = (async (name: string) =>
				name === `_443._tcp.${fx.domain}` ? fx.tlsa : []) as never;
			const rawQueryDNS = (async () => ({ AD: fx.ad })) as never;
			const result = await checkDANEHTTPS(fx.domain, queryDNS, { rawQueryDNS });
			expect({ score: result.score, missing: missingControl(result.findings) }).toEqual({
				score: fx.expectedScore,
				missing: fx.expectedMissingControl,
			});
		});
	}
});

describe('SVCB-HTTPS parity corpus — bv-mcp full checkSVCBHTTPS', () => {
	for (const fx of SVCB_HTTPS_PARITY_FIXTURES) {
		it(`scores "${fx.name}" → ${fx.expectedScore} (missingControl=${fx.expectedMissingControl})`, async () => {
			const queryDNS = (async (name: string, type: string) =>
				type === 'HTTPS' && name === fx.domain ? fx.https : []) as never;
			const result = await checkSVCBHTTPS(fx.domain, queryDNS);
			expect({ score: result.score, missing: missingControl(result.findings) }).toEqual({
				score: fx.expectedScore,
				missing: fx.expectedMissingControl,
			});
		});
	}
});
