// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { checkSecurityTxt } from '../../checks/check-security-txt';
import { parseSecurityTxt } from '../../checks/security-txt-analysis';
import type { CheckResult, FetchFunction } from '../../types';

const NOW = new Date('2026-06-01T00:00:00Z');
const WELL_KNOWN = 'https://example.com/.well-known/security.txt';
const LEGACY = 'https://example.com/security.txt';

const VALID = ['Contact: mailto:security@example.com', 'Expires: 2026-12-31T23:59:59Z', 'Policy: https://example.com/policy', `Canonical: ${WELL_KNOWN}`].join('\n');

const text = (body: string, status = 200, type = 'text/plain; charset=utf-8') => new Response(body, { status, headers: { 'content-type': type } });

function routes(table: Record<string, () => Response>): FetchFunction & ReturnType<typeof vi.fn> {
	return vi.fn(async (url: string) => {
		const answer = table[url];
		if (!answer) throw new Error(`unrouted ${url}`);
		return answer();
	});
}

const run = (table: Record<string, () => Response>): Promise<CheckResult> => checkSecurityTxt('example.com', routes(table), { now: NOW });
const titles = (r: CheckResult) => r.findings.map((f) => f.title);
const severityOf = (r: CheckResult, title: string) => r.findings.find((f) => f.title === title)?.severity;

describe('checkSecurityTxt', () => {
	it('clean valid file: no finding above info (positive control)', async () => {
		const r = await run({ [WELL_KNOWN]: () => text(VALID) });
		expect(r.findings.every((f) => f.severity === 'info')).toBe(true);
		expect(titles(r)).toContain('Valid security.txt found');
		expect(r.findings[0].metadata).toMatchObject({ contactCount: 1, policy: ['https://example.com/policy'], location: 'well-known' });
	});

	it('absent on both paths is a low finding', async () => {
		const r = await run({ [WELL_KNOWN]: () => text('', 404), [LEGACY]: () => text('', 404) });
		expect(severityOf(r, 'No security.txt found')).toBe('low');
		expect(r.checkStatus).toBeUndefined();
	});

	it('legacy path only: low finding, file still parsed', async () => {
		const r = await run({ [WELL_KNOWN]: () => text('', 404), [LEGACY]: () => text(VALID.replace(/Canonical:.*/, '')) });
		expect(severityOf(r, 'security.txt found only at the legacy path')).toBe('low');
		expect(titles(r)).not.toContain('security.txt is missing Contact');
	});

	it('HTML served with 200 is a medium finding, not a present file', async () => {
		const r = await run({ [WELL_KNOWN]: () => text('<!DOCTYPE html><html><body>Not found</body></html>', 200, 'text/html') });
		expect(severityOf(r, 'security.txt is served as an HTML page')).toBe('medium');
		expect(titles(r)).not.toContain('Valid security.txt found');
	});

	it('HTML body under a text/plain header is still caught', async () => {
		const r = await run({ [WELL_KNOWN]: () => text('<html><head></head></html>') });
		expect(titles(r)).toContain('security.txt is served as an HTML page');
	});

	it('expired Expires is medium', async () => {
		const r = await run({ [WELL_KNOWN]: () => text(VALID.replace('2026-12-31T23:59:59Z', '2026-01-01T00:00:00Z')) });
		expect(severityOf(r, 'security.txt has expired')).toBe('medium');
	});

	it('Expires over a year ahead is low', async () => {
		const r = await run({ [WELL_KNOWN]: () => text(VALID.replace('2026-12-31T23:59:59Z', '2028-01-01T00:00:00Z')) });
		expect(severityOf(r, 'security.txt Expires is more than a year ahead')).toBe('low');
	});

	it('missing Contact and missing Expires are medium', async () => {
		const r = await run({ [WELL_KNOWN]: () => text(`Policy: https://example.com/policy\nCanonical: ${WELL_KNOWN}`) });
		expect(severityOf(r, 'security.txt is missing Contact')).toBe('medium');
		expect(severityOf(r, 'security.txt is missing Expires')).toBe('medium');
	});

	it('Contact that is not a URI is low', async () => {
		const r = await run({ [WELL_KNOWN]: () => text(VALID.replace('mailto:security@example.com', 'security@example.com')) });
		expect(severityOf(r, 'security.txt Contact is not a URI')).toBe('low');
	});

	it('Canonical that omits the fetched URL is low', async () => {
		const r = await run({ [WELL_KNOWN]: () => text(VALID.replace(WELL_KNOWN, 'https://other.example/.well-known/security.txt')) });
		expect(severityOf(r, 'security.txt Canonical does not include its own URL')).toBe('low');
	});

	it('PGP-signed file reports an info finding and still validates its fields', async () => {
		const signed = ['-----BEGIN PGP SIGNED MESSAGE-----', 'Hash: SHA256', '', VALID, '-----BEGIN PGP SIGNATURE-----', '', 'abc', '-----END PGP SIGNATURE-----'].join('\n');
		const r = await run({ [WELL_KNOWN]: () => text(signed) });
		expect(severityOf(r, 'security.txt is PGP-signed')).toBe('info');
		expect(r.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('network failure is not assessed, never absent', async () => {
		const r = await checkSecurityTxt('example.com', routes({}), { now: NOW });
		expect(r).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
	});

	it('a 403 on the well-known path is not assessed', async () => {
		const r = await run({ [WELL_KNOWN]: () => text('', 403) });
		expect(r.checkStatus).toBe('error');
	});
});

describe('parseSecurityTxt', () => {
	it('collects repeated fields, ignores comments and unknown fields', () => {
		const p = parseSecurityTxt('# note\nContact: a\ncontact: b\nEncryption: https://k\nX-Unknown: 1\nExpires: nonsense');
		expect(p.contacts).toEqual(['a', 'b']);
		expect(p.encryption).toEqual(['https://k']);
		expect(p.expiresAt).toBeNull();
		expect(p.signed).toBe(false);
	});

	it('trims tabs and spaces after the colon, and a tab-flooded line parses in linear time', () => {
		expect(parseSecurityTxt('Contact:\t \tmailto:a@example.com').contacts).toEqual(['mailto:a@example.com']);
		const started = performance.now();
		const p = parseSecurityTxt(`A:${'\t'.repeat(50_000)}x`);
		expect(performance.now() - started).toBeLessThan(250);
		expect(p.contacts).toEqual([]);
	});
});
