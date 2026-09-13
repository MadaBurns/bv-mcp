// SPDX-License-Identifier: BUSL-1.1

/**
 * Regression tests for bv-mcp #988 — the SPF `all` qualifier on the FINDING path.
 *
 * The finding path used to extract the qualifier with an unanchored substring
 * scan (`spf.match(/[+?~-]all/i)`), so a HOSTNAME containing `-all` / `+all` /
 * `?all` anywhere before the terminal mechanism won the match. `send-all.`,
 * `mail-all.` and `smtp-all.` are ordinary names, so this was reachable on real
 * records in both directions: a soft-fail record silently emitting no soft-fail
 * finding, and a hard-fail record being called permissive.
 *
 * A bare `all` was not matched at all, though RFC 7208 §4.6.2 gives an
 * unqualified mechanism the implicit `+` — the MOST permissive disposition.
 *
 * These assertions are SCORE-BEARING: each finding that appears or disappears
 * moves the spf category score. That is the point of the fix, not a side effect.
 */

import { describe, it, expect, vi } from 'vitest';
import { checkSPF } from '../../checks/check-spf';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => records[domain] ?? []);
}

/** No DMARC record, so the `~all` branch lands on the plain "SPF soft fail (~all)" leg. */
function dns(spf: string): DNSQueryFunction {
	return createMockDNS({ 'example.com': [spf], '_dmarc.example.com': [] });
}

describe('SPF `all` qualifier is read from a whole term, not a substring (#988)', () => {
	it('emits the soft-fail finding when a hostname contains "-all" before the terminal ~all', async () => {
		// Old behaviour: `-all` matched inside `send-all.example.net`, so neither the
		// RISKY_MECHANISMS branch nor the `~all` branch fired — the record scored as
		// though it published hard fail.
		const result = await checkSPF('example.com', dns('v=spf1 include:send-all.example.net ~all'));
		const softFail = result.findings.find((f) => f.title === 'SPF soft fail (~all)');
		expect(softFail).toBeDefined();
		expect(softFail?.severity).toBe('low');
	});

	it('does not call a hard-fail record permissive when a hostname contains "+all"', async () => {
		// The inverse false positive: a critical "Permissive SPF" claim against a
		// domain that actually publishes `-all`.
		const result = await checkSPF('example.com', dns('v=spf1 include:send+all.example.net -all'));
		expect(result.findings.some((f) => f.title.startsWith('Permissive SPF'))).toBe(false);
		expect(result.findings.some((f) => f.title === "No 'all' mechanism")).toBe(false);
	});

	it('flags a bare `all` as permissive — RFC 7208 §4.6.2 implicit "+"', async () => {
		// Worst case: unqualified `all` authorises every sender. Old behaviour emitted
		// the MEDIUM "No 'all' mechanism" finding instead of the CRITICAL one.
		const result = await checkSPF('example.com', dns('v=spf1 include:_spf.example.net all'));
		const permissive = result.findings.find((f) => f.title.startsWith('Permissive SPF'));
		expect(permissive).toBeDefined();
		expect(permissive?.severity).toBe('critical');
		expect(permissive?.title).toBe('Permissive SPF: +all');
		expect(result.findings.some((f) => f.title === "No 'all' mechanism")).toBe(false);
	});

	it('reads the `all` term when further terms follow it', async () => {
		// `exp=` legitimately follows the terminal mechanism, and the decoy hostname
		// sits earlier in the record.
		const result = await checkSPF('example.com', dns('v=spf1 include:send-all.example.net +all exp=why.example.net'));
		const permissive = result.findings.find((f) => f.title.startsWith('Permissive SPF'));
		expect(permissive).toBeDefined();
		expect(permissive?.severity).toBe('critical');
		expect(permissive?.title).toBe('Permissive SPF: +all');
	});

	it('takes the FIRST `all` term when a record carries two — RFC 7208 §5.1', async () => {
		// `all` always matches, so evaluation never reaches the second one. (Both the
		// old and new extractions agree here; asserted to lock the documented rule.)
		const result = await checkSPF('example.com', dns('v=spf1 ~all -all'));
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all)')).toBe(true);
	});

	it('reports a record with NO `all` term as missing one, even behind a decoy hostname', async () => {
		// RFC 7208 §5.1: `all` always matches when present, so its ABSENCE is a
		// distinct state (default neutral). Old behaviour matched `-all` inside the
		// hostname and emitted nothing at all — a false clean.
		const result = await checkSPF('example.com', dns('v=spf1 include:send-all.example.net'));
		const missing = result.findings.find((f) => f.title === "No 'all' mechanism");
		expect(missing).toBeDefined();
		expect(missing?.severity).toBe('medium');
	});

	it('leaves a clean -all record with no `all`-related finding (control)', async () => {
		const result = await checkSPF('example.com', dns('v=spf1 include:_spf.example.net -all'));
		expect(result.findings.some((f) => f.title.startsWith('Permissive SPF'))).toBe(false);
		expect(result.findings.some((f) => f.title.startsWith('SPF soft fail'))).toBe(false);
		expect(result.findings.some((f) => f.title === "No 'all' mechanism")).toBe(false);
	});

	it('keeps the finding path and the `spfAll` metadata signal in agreement (one extraction)', async () => {
		// #987 fixed the metadata signal only; #988 makes the finding path reuse the
		// SAME extraction. This asserts they cannot diverge again on the decoy shape.
		const result = await checkSPF('example.com', dns('v=spf1 include:send-all.example.net ~all'));
		expect(result.metadata?.spfAll).toBe('~all');
		expect(result.findings.some((f) => f.title === 'SPF soft fail (~all)')).toBe(true);
	});
});
