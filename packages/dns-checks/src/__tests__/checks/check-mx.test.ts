// SPDX-License-Identifier: BUSL-1.1

/**
 * #1114 — `checkMX` must not count a syntactically invalid MX exchange as a live
 * mail control. `sevicenow.com` publishes `MX 300 ~.`; before the fix `checkMX`
 * returned `controlPresent: true`, "MX records found" and a `medium` "Dangling MX
 * record" for the literal `~`, so `scan_domain`'s non-mail post-processing never
 * applied. "Dangling MX" stays reserved for a SYNTACTICALLY VALID name that does
 * not resolve (the positive control below).
 */

import { describe, it, expect } from 'vitest';
import { checkMX } from '../../checks/check-mx';
import type { DNSQueryFunction } from '../../types';

/** MX answers for the apex; optional TXT; every A/AAAA empty unless listed in `resolves`. */
function zone(mx: string[], opts: { txt?: string[]; resolves?: string[] } = {}): { dns: DNSQueryFunction; lookups: string[] } {
	const lookups: string[] = [];
	const dns: DNSQueryFunction = async (name, type) => {
		lookups.push(`${type} ${name}`);
		if (type === 'MX') return mx;
		if (type === 'TXT') return opts.txt ?? [];
		if ((type === 'A' || type === 'AAAA') && opts.resolves?.includes(name)) return type === 'A' ? ['192.0.2.1'] : [];
		return [];
	};
	return { dns, lookups };
}

describe('checkMX — invalid MX exchange (#1114)', () => {
	it('`300 ~.` is NOT a present mail control and is NOT reported as dangling', async () => {
		const { dns, lookups } = zone(['300 ~.']);
		const result = await checkMX('sevicenow.example', dns);

		expect(result.controlPresent).toBe(false);
		const invalid = result.findings.find((f) => f.title === 'Invalid MX exchange hostname');
		expect(invalid).toBeDefined();
		expect(invalid!.severity).toBe('low');
		expect(invalid!.detail).toContain('"~"');
		expect(result.findings.find((f) => f.title === 'Dangling MX record')).toBeUndefined();
		expect(result.findings.find((f) => f.title === 'MX records found')).toBeUndefined();
		// The literal is never resolved as a hostname.
		expect(lookups.some((l) => l.endsWith(' ~'))).toBe(false);
		// No-mail SPF context applies exactly as for a zone with no MX at all.
		expect(result.findings.find((f) => f.title === 'No MX and no SPF — domain spoofable')).toBeDefined();
	});

	it('an underscore exchange with a hard-fail SPF reads as a non-mail domain plus the invalid finding', async () => {
		const { dns } = zone(['10 mail_server.example.com.'], { txt: ['v=spf1 -all'] });
		const result = await checkMX('underscore.example', dns);

		expect(result.controlPresent).toBe(false);
		expect(result.findings.map((f) => f.title).sort()).toEqual(['Correctly-configured non-mail domain', 'Invalid MX exchange hostname']);
		expect(result.findings.find((f) => f.title === 'Invalid MX exchange hostname')!.detail).toContain('mail_server.example.com');
	});

	it('POSITIVE CONTROL: a syntactically valid exchange that does not resolve still yields "Dangling MX record"', async () => {
		const { dns } = zone(['10 ghost.example.com.']);
		const result = await checkMX('dangling.example', dns);

		expect(result.controlPresent).toBe(true);
		const dangling = result.findings.find((f) => f.title === 'Dangling MX record');
		expect(dangling).toBeDefined();
		expect(dangling!.severity).toBe('medium');
		expect(dangling!.detail).toContain('ghost.example.com');
		expect(result.findings.find((f) => f.title === 'Invalid MX exchange hostname')).toBeUndefined();
	});

	it('MIXED: one valid + one invalid exchange stays a mail control; the invalid one is named, never probed', async () => {
		const { dns, lookups } = zone(['10 mx.example.com.', '300 ~.'], { resolves: ['mx.example.com'] });
		const result = await checkMX('mixed.example', dns);

		expect(result.controlPresent).toBe(true);
		const invalid = result.findings.find((f) => f.title === 'Invalid MX exchange hostname');
		expect(invalid).toBeDefined();
		expect(invalid!.detail).toContain('"~"');
		expect(invalid!.detail).not.toContain('mx.example.com');
		expect(result.findings.find((f) => f.title === 'Dangling MX record')).toBeUndefined();
		expect(result.findings.find((f) => f.title === 'MX records found')!.detail).toContain('1 mail exchange record');
		expect(lookups.some((l) => l.endsWith(' ~'))).toBe(false);
		expect(lookups).toContain('A mx.example.com');
	});

	it('loopback behaviour is unchanged by the invalid-exchange pass (#944 Option A)', async () => {
		const { dns } = zone(['0 localhost.']);
		const result = await checkMX('loopback.example', dns);
		expect(result.controlPresent).toBe(true);
		expect(result.findings.find((f) => f.title === 'MX points at localhost')).toBeDefined();
		expect(result.findings.find((f) => f.title === 'Invalid MX exchange hostname')).toBeUndefined();
		expect(result.score).toBe(80);
	});
});
