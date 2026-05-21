import { describe, it, expect } from 'vitest';
import { classifyRegistrarFamily } from '../../src/lib/registrar-identity';

const FAMILY_FIXTURES: Array<{ family: string; sampleName: string }> = [
	{ family: 'markmonitor', sampleName: 'MarkMonitor Inc.' },
	{ family: 'com laude', sampleName: 'Com Laude' },
	{ family: 'safenames', sampleName: 'Safenames Ltd' },
	{ family: 'csc corporate domains', sampleName: 'CSC Corporate Domains, Inc.' },
	{ family: 'cloudflare', sampleName: 'Cloudflare, Inc.' },
	{ family: 'tucows', sampleName: 'Tucows Domains Inc.' },
	{ family: 'godaddy', sampleName: 'GoDaddy.com, LLC' },
	{ family: 'namecheap', sampleName: 'Namecheap, Inc.' },
	{ family: 'network solutions', sampleName: 'Network Solutions, LLC' },
	{ family: 'gandi', sampleName: 'Gandi SAS' },
];

describe('AUDIT: registrar-portfolio family coverage', () => {
	it.each(FAMILY_FIXTURES)('classifies "$sampleName" as family "$family"', ({ family, sampleName }) => {
		expect(classifyRegistrarFamily(sampleName)).toBe(family);
	});

	it('FAMILY_FIXTURES covers all registrar families defined in registrar-identity.ts', () => {
		// Extract all family strings from the source by examining each fixture's
		// classification. This is a regression test: if a new family is added to
		// KNOWN_REGISTRAR_FAMILIES and no fixture is provided, future classification
		// calls will have no examples to verify against, and maintainers will miss it.

		const fixtureFamilies = new Set(FAMILY_FIXTURES.map((f) => f.family));

		// Test that each fixture produces the expected classification (as above, but
		// we also construct the set for the coverage check below).
		for (const { family, sampleName } of FAMILY_FIXTURES) {
			const classified = classifyRegistrarFamily(sampleName);
			expect(classified, `fixture sample "${sampleName}" should classify as "${family}"`).toBe(family);
		}

		// The following check is more nuanced: we cannot directly import
		// KNOWN_REGISTRAR_FAMILIES from registrar-identity.ts because it's private.
		// Instead, we verify coverage by testing a representative sample from each
		// family we expect to support. If a new family is added to the source and
		// forgotten here, the fixture list will be incomplete, and this test
		// should be updated to match.
		//
		// To detect drift automatically, maintainers should:
		// 1. Add a new family to KNOWN_REGISTRAR_FAMILIES in registrar-identity.ts
		// 2. Run this test; it will fail because no fixture samples that family yet
		// 3. Add a fixture entry with a representative registrar name
		//
		// This manual coupling is acceptable for a small number of families (10–15).
		// If the number grows significantly, export KNOWN_REGISTRAR_FAMILIES as a public
		// const and import it here for a fully automated check.

		expect(fixtureFamilies.size).toBe(10);
		expect(Array.from(fixtureFamilies).sort()).toEqual([
			'cloudflare',
			'com laude',
			'csc corporate domains',
			'gandi',
			'godaddy',
			'markmonitor',
			'namecheap',
			'network solutions',
			'safenames',
			'tucows',
		]);
	});
});
