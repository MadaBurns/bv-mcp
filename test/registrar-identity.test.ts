// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

import {
	normalizeRegistrarIdentity,
	sameRegistrarFamily,
	type RegistrarIdentity,
} from '../src/lib/registrar-identity';

describe('registrar identity matching', () => {
	it('matches the same IANA registrar ID even when registrar names differ', () => {
		const left: RegistrarIdentity = { name: 'CSC Corporate Domains, Inc.', ianaId: '299' };
		const right: RegistrarIdentity = { name: 'Corporation Service Company', ianaId: '299' };

		expect(sameRegistrarFamily(left, right)).toBe(true);
	});

	it('does not match unrelated registrars by weak suffix or token overlap', () => {
		expect(
			sameRegistrarFamily(
				{ name: 'GoDaddy Corporate Domains, LLC', ianaId: '146' },
				{ name: 'CSC Corporate Domains, Inc.', ianaId: '299' },
			),
		).toBe(false);

		expect(
			sameRegistrarFamily(
				{ name: 'Example Consumer Domains LLC' },
				{ name: 'Example Corporate Domains Inc.' },
			),
		).toBe(false);
	});

	it('does not match known registrar names as substrings inside unrelated names', () => {
		expect(sameRegistrarFamily({ name: 'Ugandi Registrar LLC' }, { name: 'Gandi SAS' })).toBe(false);
		expect(sameRegistrarFamily({ name: 'Not Cloudflare Domains LLC' }, { name: 'Cloudflare Registrar LLC' })).toBe(false);
	});

	it('strips corporate suffixes without deleting meaningful tokens', () => {
		expect(normalizeRegistrarIdentity('CSC Corporate Domains, Inc.')).toBe('csc corporate domains');
	});
});
