// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure-parser coverage for the DKIM record abuse-surface tags.
 *
 * Scope note: `x=` (signature expiry) and `l=` (body-length) are the tags that actually
 * govern DKIM replay exposure, but RFC 6376 places them in the per-message DKIM-Signature
 * HEADER (§3.5), not the DNS key record (§3.6.1). A passive DNS scanner never sees a
 * message, so there is deliberately no parser for them here.
 */

import { describe, it, expect } from 'vitest';
import { parseDkimFlags, analyzeHashRestriction, analyzeServiceTypes } from '../../checks/dkim-analysis';

describe('parseDkimFlags', () => {
	it('returns all-false when t= is absent', () => {
		expect(parseDkimFlags('v=DKIM1; k=rsa; p=AAAA')).toEqual({ testMode: false, strictSubdomain: false, flags: [] });
	});

	it('parses t=y as test mode', () => {
		expect(parseDkimFlags('v=DKIM1; t=y; p=AAAA').testMode).toBe(true);
	});

	it('parses flags in either order', () => {
		expect(parseDkimFlags('v=DKIM1; t=y:s; p=AAAA')).toMatchObject({ testMode: true, strictSubdomain: true });
		// The ordering the old /t=y/ substring scan missed.
		expect(parseDkimFlags('v=DKIM1; t=s:y; p=AAAA')).toMatchObject({ testMode: true, strictSubdomain: true });
	});

	it('parses t=s alone as strict-only, never test mode', () => {
		expect(parseDkimFlags('v=DKIM1; t=s; p=AAAA')).toMatchObject({ testMode: false, strictSubdomain: true });
	});

	it('tolerates whitespace and case', () => {
		expect(parseDkimFlags('v=DKIM1;  t = Y ; p=AAAA').testMode).toBe(true);
	});

	it('ignores a t=y substring inside another tag value', () => {
		expect(parseDkimFlags('v=DKIM1; n=remove t=y after rollout; p=AAAA').testMode).toBe(false);
	});

	it('does not read a tag whose name merely ends in t', () => {
		expect(parseDkimFlags('v=DKIM1; nt=y; p=AAAA').testMode).toBe(false);
	});

	it('retains unknown flags without inventing meaning', () => {
		expect(parseDkimFlags('v=DKIM1; t=y:z; p=AAAA').flags).toEqual(['y', 'z']);
	});

	it('treats an empty t= as no flags', () => {
		expect(parseDkimFlags('v=DKIM1; t=; p=AAAA')).toEqual({ testMode: false, strictSubdomain: false, flags: [] });
	});
});

describe('analyzeHashRestriction', () => {
	it('returns null when h= is absent', () => {
		expect(analyzeHashRestriction('v=DKIM1; k=rsa; p=AAAA')).toBeNull();
	});

	it('returns null for a healthy sha256-only restriction', () => {
		expect(analyzeHashRestriction('v=DKIM1; h=sha256; p=AAAA')).toBeNull();
	});

	it('classifies sha1 without sha256 as sha1-only', () => {
		expect(analyzeHashRestriction('v=DKIM1; h=sha1; p=AAAA')).toEqual({ algorithms: ['sha1'], kind: 'sha1-only' });
	});

	it('classifies a restriction omitting both sha256 and sha1 as no-sha256', () => {
		expect(analyzeHashRestriction('v=DKIM1; h=sha512; p=AAAA')).toEqual({ algorithms: ['sha512'], kind: 'no-sha256' });
	});

	it('classifies sha1 listed alongside sha256 as sha1-permitted', () => {
		expect(analyzeHashRestriction('v=DKIM1; h=sha256:sha1; p=AAAA')).toEqual({
			algorithms: ['sha256', 'sha1'],
			kind: 'sha1-permitted',
		});
	});

	it('is order- and case-insensitive', () => {
		expect(analyzeHashRestriction('v=DKIM1; h=SHA1 : SHA256; p=AAAA')?.kind).toBe('sha1-permitted');
	});

	it('does not mistake a sha1-prefixed algorithm name for sha1', () => {
		// Exact-token comparison, so "sha1024"-shaped values cannot masquerade as sha1.
		expect(analyzeHashRestriction('v=DKIM1; h=sha1024; p=AAAA')).toEqual({ algorithms: ['sha1024'], kind: 'no-sha256' });
	});

	it('returns null for an empty h=', () => {
		expect(analyzeHashRestriction('v=DKIM1; h=; p=AAAA')).toBeNull();
	});
});

describe('analyzeServiceTypes', () => {
	it('returns null when s= is absent', () => {
		expect(analyzeServiceTypes('v=DKIM1; k=rsa; p=AAAA')).toBeNull();
	});

	it('returns null for an empty s= (defaults to *)', () => {
		expect(analyzeServiceTypes('v=DKIM1; s=; p=AAAA')).toBeNull();
	});

	it('treats s=* as covering email', () => {
		expect(analyzeServiceTypes('v=DKIM1; s=*; p=AAAA')).toEqual({ services: ['*'], coversEmail: true });
	});

	it('treats s=email as covering email', () => {
		expect(analyzeServiceTypes('v=DKIM1; s=email; p=AAAA')?.coversEmail).toBe(true);
	});

	it('treats email anywhere in the list as covering email', () => {
		expect(analyzeServiceTypes('v=DKIM1; s=web:email; p=AAAA')?.coversEmail).toBe(true);
	});

	it('flags a list that admits neither email nor the wildcard', () => {
		expect(analyzeServiceTypes('v=DKIM1; s=web; p=AAAA')).toEqual({ services: ['web'], coversEmail: false });
	});

	it('is case- and whitespace-insensitive', () => {
		expect(analyzeServiceTypes('v=DKIM1; s= EMAIL ; p=AAAA')?.coversEmail).toBe(true);
	});
});
