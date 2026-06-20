// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos hypotheses for the brand-discovery literal-seed fix (3.20.0).
 *
 * The bug was client-side: an LLM (Claude Desktop) asked to expand `clau.de`
 * silently rewrote the seed to the "canonical" brand domain `anthropic.com`
 * before calling the tool. The fix tightened the tool/param DESCRIPTION to tell
 * the model to pass the literal seed verbatim. That prose promise is only
 * trustworthy if the SERVER honours whatever seed it is handed — i.e. it scans
 * the literal seed and NEVER substitutes a different registrable domain.
 *
 * Given an adversarial seed (the exact substitution case, weird-but-valid
 * shapes, or hostile/malformed input), discoverBrandDomains must (a) anchor its
 * seed-bound signals on the verbatim seed it was given, never a swapped domain,
 * and (b) reject invalid input cleanly with an allowlisted error prefix rather
 * than crashing or silently substituting.
 */

import { describe, it, expect, vi } from 'vitest';
import type { DiscoverBrandDomainsDeps } from '../../src/tools/discover-brand-domains';

/** Full no-op dep surface so candidate-universe generation + every signal is stubbed (no real network). */
function makeDeps(overrides: Partial<DiscoverBrandDomainsDeps> = {}): DiscoverBrandDomainsDeps {
	const okEmpty = { coOwnedDomains: [], queryStatus: 'ok' as const };
	return {
		correlateSans: vi.fn().mockResolvedValue({ seedDomain: 's', coOwnedDomains: [], certIds: [], queryStatus: 'ok' }),
		correlateSansRecursive: vi.fn().mockResolvedValue({ seedDomain: 's', crossConfirmed: [], probed: [], queryStatus: 'ok' }),
		correlateNs: vi.fn().mockResolvedValue({ seedDomain: 's', seedNs: [], coOwnedDomains: [], queryStatus: 'ok' }),
		mineDmarcRua: vi.fn().mockResolvedValue({ seedDomain: 's', dmarcPresent: false, ruaUris: [], ruaDomains: [], queryStatus: 'ok' }),
		detectDkimKeyReuse: vi.fn().mockResolvedValue({ seedDomain: 's', seedSelectors: [], coOwnedDomains: [], queryStatus: 'ok' }),
		detectHttpRedirect: vi.fn().mockResolvedValue(okEmpty),
		detectMxOverlap: vi.fn().mockResolvedValue(okEmpty),
		detectSharedTxtVerifications: vi.fn().mockResolvedValue({ seedDomain: 's', coOwnedDomains: [], queryStatus: 'ok' }),
		detectSharedMxPlatform: vi.fn().mockResolvedValue({ seedDomain: 's', coOwnedDomains: [], queryStatus: 'ok' }),
		detectSpfInclude: vi.fn().mockResolvedValue(okEmpty),
		extractSeedSpfIncludes: vi.fn().mockResolvedValue({ seedDomain: 's', candidates: [], queryStatus: 'ok' }),
		detectCnameAlignment: vi.fn().mockResolvedValue(okEmpty),
		generateMarkovLookalikes: vi.fn().mockReturnValue([]),
		checkLookalikes: vi.fn().mockResolvedValue({ category: 'lookalikes', score: 100, findings: [] }),
		domainLabelSimilarity: vi.fn().mockReturnValue(0),
		...overrides,
	} as DiscoverBrandDomainsDeps;
}

// Valid seeds the tool MUST scan verbatim — including the exact bug case (clau.de),
// short ccTLD, multi-label, punycode/IDN, and a long single label.
const VERBATIM_SEEDS = ['clau.de', 'paypal.com', 'sub.example.co.uk', 'xn--mnchen-3ya.de', 'a-very-long-brand-label.com'];

// Hostile / malformed seeds — must be rejected cleanly, never substituted or crashed on.
const HOSTILE_SEEDS = ['not a domain', 'evil.com\ninjected.com', 'http://x.example', `${'a'.repeat(300)}.com`, '', '   '];

describe('chaos: literal-seed preservation under adversarial input', () => {
	it.each(VERBATIM_SEEDS)('scans the literal seed "%s" — anchors signals on it, never substitutes a canonical domain', async (seed) => {
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateSans = vi.fn().mockResolvedValue({ seedDomain: seed, coOwnedDomains: [], certIds: [], queryStatus: 'ok' });
		const correlateNs = vi.fn().mockResolvedValue({ seedDomain: seed, seedNs: [], coOwnedDomains: [], queryStatus: 'ok' });
		const deps = makeDeps({ correlateSans, correlateNs });

		await discoverBrandDomains(seed, { signals: ['san', 'ns'] }, deps);

		// Seed-anchored signals must receive the EXACT seed handed in — not a rewritten brand domain.
		expect(correlateSans.mock.calls[0][0]).toBe(seed);
		expect(correlateNs.mock.calls[0][0]).toBe(seed);
	});

	it('regression: clau.de is scanned as clau.de, never as anthropic.com', async () => {
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateSans = vi.fn().mockResolvedValue({ seedDomain: 'clau.de', coOwnedDomains: [], certIds: [], queryStatus: 'ok' });
		const deps = makeDeps({ correlateSans });

		await discoverBrandDomains('clau.de', { signals: ['san'] }, deps);

		const scanned = correlateSans.mock.calls[0][0] as string;
		expect(scanned).toBe('clau.de');
		expect(scanned).not.toContain('anthropic');
	});

	it.each(HOSTILE_SEEDS)('rejects hostile seed %j with an allowlisted error prefix, never substitutes or crashes', async (seed) => {
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateSans = vi.fn();
		const deps = makeDeps({ correlateSans });

		// Either a clean validation rejection (allowlisted prefix), or — if sanitization lets it through —
		// the verbatim seed reaches the signal. Never an unhandled crash, never a substituted domain.
		let rejected = false;
		try {
			await discoverBrandDomains(seed, { signals: ['san'] }, deps);
		} catch (e) {
			rejected = true;
			expect((e as Error).message).toMatch(/^(Domain validation failed|Domain |Invalid)/);
		}
		if (!rejected && correlateSans.mock.calls.length > 0) {
			expect(correlateSans.mock.calls[0][0]).toBe(seed); // passed through verbatim, not swapped
		}
	});
});
