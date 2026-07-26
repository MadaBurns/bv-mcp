import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

describe('compareDomains', () => {
	beforeEach(() => {
		globalThis.fetch = vi.fn().mockResolvedValue(new Response('OK', { status: 200 }));
	});

	it('should compare 2 domains and return structured result', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'test.com'], { kv: env.SCAN_CACHE });
		expect(result.domains).toHaveLength(2);
		expect(typeof result.winner === 'string' || result.winner === null).toBe(true);
		expect(Array.isArray(result.commonGaps)).toBe(true);
		expect(Array.isArray(result.categoryComparison)).toBe(true);
	});

	it('should reject fewer than 2 domains', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		await expect(compareDomains(['only.com'])).rejects.toThrow(/at least 2/i);
	});

	it('should reject more than 5 domains', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		await expect(compareDomains(['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com'])).rejects.toThrow(/max.*5/i);
	});

	it('should include errors for invalid domains without throwing', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'invalid!@#domain'], { kv: env.SCAN_CACHE });
		expect(Object.keys(result.errors).length).toBeGreaterThan(0);
	});

	it('returns null winner when only 1 domain scanned successfully', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'invalid!@#domain'], { kv: env.SCAN_CACHE });
		// Only example.com scans successfully; winner should be null (< 2 valid results)
		expect(result.winner).toBeNull();
	});

	it('excludes an ungraded domain from ranking and never renders a fabricated F for it', async () => {
		const { compareDomains, formatDomainComparison } = await import('../src/tools/compare-domains');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const scanStub = (async (domain: string): Promise<any> => ({
			domain,
			score:
				domain === 'ungraded.com'
					? { overall: 0, grade: 'N/A', summary: 'unscored', categoryScores: {}, findings: [] }
					: { overall: 80, grade: 'B', summary: 'ok', categoryScores: {}, findings: [] },
			checks: domain === 'ungraded.com' ? [] : [{ category: 'spf', passed: true, score: 80, findings: [] }],
			maturity: { stage: 2, label: 'Baseline', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		})) as any;

		const result = await compareDomains(['graded.com', 'ungraded.com'], { scanFn: scanStub });

		// `measured: false` for the unscored domain must exclude it from the winner race,
		// so a 2-domain compare has only ONE rankable entry and therefore no winner.
		expect(result.winner).toBeNull();
		expect(result.grades['graded.com']).toBe('B');

		const text = formatDomainComparison(result, 'compact');
		expect(text).toContain('not measured');
		// Locate the ungraded domain's own line — asserting on the exact padded column
		// width is fragile (a prior version of this test miscounted the padEnd(40) gap
		// by one space and could never fail) — and confirm it never renders a score.
		const ungradedLine = text.split('\n').find((line) => line.includes('ungraded.com'));
		expect(ungradedLine).toBeDefined();
		expect(ungradedLine).not.toContain('/100');
	});
});

/**
 * `categoryComparison` fabricated a full set of per-category FAILURES for a domain
 * that was never measured, and deleted a real one from the domain that was.
 *
 * Task 4 fixed the headline score/grade and the winner race, but the comparison was
 * still built over every valid result with `r.categoryScores[category] ?? 0`. An
 * unmeasured domain's `categoryScores` is `{}`, so every category coerced to 0:
 *   - ~18 named "unique weaknesses" for a domain nobody looked at, printed directly
 *     beneath its own "not measured" line;
 *   - `✗ 0` down its whole column in the full-format table;
 *   - `{"lapsed.kiwi":0}` per category in `structuredContent.categoryComparison`;
 *   - and — the mirror — the MEASURED domain's genuine DMARC weakness DELETED from
 *     `uniqueGaps`, because `others.every(s => s >= 50)` saw the fabricated 0.
 *
 * The prior fixture here gave BOTH stub domains `categoryScores: {}` and asserted
 * only against `'compact'` (which hides the table), so it could not reach any of
 * this. These fixtures carry real per-category scores including one genuine
 * weakness, and assert against both formats AND the serialized payload.
 */
describe('compareDomains — per-category claims about an unmeasured domain', () => {
	/** A measured scan with real per-category scores. */
	function measured(domain: string, categoryScores: Record<string, number>, overall: number, grade: string, profile = 'mail_enabled') {
		return {
			domain,
			score: { overall, grade, summary: `Grade: ${grade}`, categoryScores, findings: [] },
			// Non-empty `checks` is what makes `measured` true; the per-category numbers
			// come from the score map.
			checks: [{ category: 'ssl', passed: true, score: 100, findings: [] }],
			maturity: { stage: 2, label: 'Baseline', description: 'x', nextStep: null },
			context: { profile, signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		};
	}

	/** The NXDOMAIN shape: zero checks, no score, an empty category map. */
	function neverMeasured(domain: string) {
		return {
			domain,
			score: { overall: null, grade: null, summary: `${domain} does not resolve`, categoryScores: {}, findings: [] },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		};
	}

	/**
	 * acme.com carries a genuine DMARC deficiency (20). healthy.net is clean.
	 * lapsed.kiwi does not resolve. Three domains, not two, because "unique among a
	 * set of one" is not a comparison — a two-domain fixture cannot show the real
	 * weakness surviving.
	 */
	async function threeDomains() {
		const { compareDomains } = await import('../src/tools/compare-domains');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const scanStub = (async (domain: string): Promise<any> => {
			if (domain === 'acme.com') return measured('acme.com', { spf: 100, dmarc: 20, dnssec: 100, ssl: 100 }, 62, 'D+');
			if (domain === 'healthy.net') return measured('healthy.net', { spf: 100, dmarc: 100, dnssec: 100, ssl: 100 }, 95, 'A');
			return neverMeasured('lapsed.kiwi');
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		}) as any;
		return compareDomains(['acme.com', 'healthy.net', 'lapsed.kiwi'], { scanFn: scanStub });
	}

	it('makes no per-category claim about the unmeasured domain', async () => {
		const result = await threeDomains();

		// Fixture-reachability guard: the comparison really was built, and really does
		// carry the categories the defect fabricated.
		expect(result.categoryComparison.length).toBeGreaterThan(0);
		expect(result.categoryComparison.map((cc) => cc.category).sort()).toEqual(['dmarc', 'dnssec', 'spf', 'ssl']);

		for (const cc of result.categoryComparison) {
			expect(Object.keys(cc.scores).sort(), cc.category).toEqual(['acme.com', 'healthy.net']);
		}
		// Was: ~18 categories named as this domain's unique weaknesses.
		expect(result.uniqueGaps.find((ug) => ug.domain === 'lapsed.kiwi')).toBeUndefined();
	});

	it("keeps the MEASURED domain's real weakness, which the fabricated zeros deleted (mirror)", async () => {
		const result = await threeDomains();

		// Was []: `others.every(s => s >= 50)` saw lapsed.kiwi's fabricated 0, so
		// acme.com's real DMARC deficiency vanished from the report purely because an
		// unmeasured sibling was in the same call.
		expect(result.uniqueGaps).toEqual([{ domain: 'acme.com', categories: ['dmarc'] }]);
		// Nothing is a common gap here — healthy.net passes everything. Was ['dmarc'],
		// because 20 and a fabricated 0 are both below 50.
		expect(result.commonGaps).toEqual([]);
	});

	it.each(['compact', 'full'] as const)('never renders a per-category verdict for the unmeasured domain [%s]', async (format) => {
		const { formatDomainComparison } = await import('../src/tools/compare-domains');
		const text = formatDomainComparison(await threeDomains(), format);

		// It is present in the report — as "not measured", once.
		expect(text, format).toContain('lapsed.kiwi');
		const lapsedLine = text.split('\n').find((l) => l.includes('lapsed.kiwi'));
		expect(lapsedLine, format).toContain('not measured');
		// …and appears nowhere else: no gap line, and (full) no table column.
		expect(
			text.split('\n').filter((l) => l.includes('lapsed.kiwi')),
			format,
		).toHaveLength(1);
		expect(text, format).not.toContain('✗ 0');
		// The real weakness is still named.
		expect(text, format).toContain('acme.com: dmarc');
	});

	it('renders the measured columns in the full table and only those (control)', async () => {
		const { formatDomainComparison } = await import('../src/tools/compare-domains');
		const full = formatDomainComparison(await threeDomains(), 'full');

		// Without this the assertions above would hold under a formatter that dropped
		// the table entirely.
		expect(full).toContain('Category Scores:');
		const dmarcRow = full.split('\n').find((l) => l.startsWith('  DMARC'));
		expect(dmarcRow).toBeDefined();
		expect(dmarcRow).toContain('✗ 20');
		expect(dmarcRow).toContain('✓ 100');
		const header = full.split('\n').find((l) => l.includes('Category') && l.includes('acme.com'));
		expect(header).toBeDefined();
		expect(header).not.toContain('lapsed.kiwi');
	});

	it('ships no fabricated zero on either serialized channel', async () => {
		const { formatDomainComparison } = await import('../src/tools/compare-domains');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const result = await threeDomains();
		const wire = buildToolResult(formatDomainComparison(result, 'full'), result, 'full');

		const structured = JSON.stringify(wire.structuredContent);
		const comment = wire.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();

		for (const [channel, payload] of [
			['structuredContent', structured],
			['STRUCTURED_RESULT', comment!],
		] as const) {
			// The banked defect verbatim.
			expect(payload, channel).not.toContain('"lapsed.kiwi":0');
			// The unmeasured domain appears only where it honestly can: as a null score.
			expect(payload, channel).toContain('"lapsed.kiwi":null');
			// …and the measured domain's real deficiency is on the wire.
			expect(payload, channel).toContain('"dmarc"');
			expect(payload, channel).toContain('"acme.com":20');
		}
	});

	/**
	 * The same `?? 0`, reached by the other route: a category measured as NOT
	 * APPLICABLE (`categoryScores[cat] === null` — MTA-STS under a non-mail profile)
	 * also coerced to a failing 0, and then read as a unique weakness.
	 */
	it('treats a not-applicable category as no score, not as a failing 0', async () => {
		const { compareDomains, formatDomainComparison } = await import('../src/tools/compare-domains');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const scanStub = (async (domain: string): Promise<any> =>
			domain === 'webonly.com'
				? // `non_mail` + mta_sts → buildStructuredScanResult reports the category as
					// N/A with a null score, however the engine scored it.
					measured('webonly.com', { ssl: 100, mta_sts: 0, dnssec: 100 }, 88, 'B', 'non_mail')
				: measured('mailer.net', { ssl: 100, mta_sts: 90, dnssec: 30 }, 70, 'C')) as unknown as Parameters<
			typeof compareDomains
		>[1]['scanFn'];

		const result = await compareDomains(['webonly.com', 'mailer.net'], { scanFn: scanStub });
		const mtaSts = result.categoryComparison.find((cc) => cc.category === 'mta_sts');

		// Fixture-reachability guard: the N/A really did reach the comparison as null.
		expect(mtaSts).toBeDefined();
		expect(mtaSts!.scores['webonly.com']).toBeNull();
		expect(mtaSts!.scores['mailer.net']).toBe(90);

		// Was [{ domain: 'webonly.com', categories: ['mta_sts'] }] — a deficiency
		// invented from a category that does not apply to this domain.
		expect(result.uniqueGaps.find((ug) => ug.domain === 'webonly.com')).toBeUndefined();
		// Control, both directions: mailer.net's real DNSSEC weakness is still unique.
		expect(result.uniqueGaps).toEqual([{ domain: 'mailer.net', categories: ['dnssec'] }]);

		const full = formatDomainComparison(result, 'full');
		const row = full.split('\n').find((l) => l.startsWith('  MTA_STS'));
		expect(row).toBeDefined();
		expect(row).toContain('not measured');
		expect(row).not.toContain('✗ 0');
	});
});
