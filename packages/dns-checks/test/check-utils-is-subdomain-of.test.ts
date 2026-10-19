// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { isSubdomainOf } from '../src/check-utils';

describe('isSubdomainOf', () => {
	it('is true for the seed itself', () => {
		expect(isSubdomainOf('example.com', 'example.com')).toBe(true);
	});

	it('is true for a subdomain of the seed, at any depth', () => {
		expect(isSubdomainOf('mail.example.com', 'example.com')).toBe(true);
		expect(isSubdomainOf('a.b.example.com', 'example.com')).toBe(true);
	});

	it('normalizes case and one trailing dot on both inputs', () => {
		expect(isSubdomainOf('Mail.Example.COM.', 'example.com')).toBe(true);
		expect(isSubdomainOf('example.com', 'EXAMPLE.com.')).toBe(true);
	});

	it('is false for an unrelated domain and for a parent of the seed', () => {
		expect(isSubdomainOf('other.org', 'example.com')).toBe(false);
		expect(isSubdomainOf('com', 'example.com')).toBe(false);
	});

	it('is false for a sibling that merely ends with the seed text (label boundary required)', () => {
		expect(isSubdomainOf('notexample.com', 'example.com')).toBe(false);
		expect(isSubdomainOf('example.com.evil.net', 'example.com')).toBe(false);
	});
});
