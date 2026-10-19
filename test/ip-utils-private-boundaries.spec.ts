// SPDX-License-Identifier: BUSL-1.1

/**
 * Exhaustive boundary pin for `isPrivateIP` (SSRF "is this a private literal" gate).
 *
 * This gate is deliberately NARROWER than `isGloballyRoutableIp`: it covers RFC 1918, loopback,
 * IPv4 link-local, `::1`, `fe80:` and ULA only. CGNAT, documentation, benchmarking, multicast,
 * and reserved ranges are NOT private here. The two gates must not be unified; this spec pins
 * the verdicts (including current quirks) so a refactor cannot drift them.
 */
import { describe, expect, it } from 'vitest';

// [address, private]. Rows come in groups: below, first, last, above.
const IPV4_BOUNDARIES: Array<[string, boolean]> = [
	// 10.0.0.0/8
	['9.255.255.255', false],
	['10.0.0.0', true],
	['10.255.255.255', true],
	['11.0.0.0', false],
	// 172.16.0.0/12
	['172.15.255.255', false],
	['172.16.0.0', true],
	['172.31.255.255', true],
	['172.32.0.0', false],
	// 192.168.0.0/16
	['192.167.255.255', false],
	['192.168.0.0', true],
	['192.168.255.255', true],
	['192.169.0.0', false],
	// 127.0.0.0/8
	['126.255.255.255', false],
	['127.0.0.0', true],
	['127.255.255.255', true],
	['128.0.0.0', false],
	// 169.254.0.0/16
	['169.253.255.255', false],
	['169.254.0.0', true],
	['169.254.255.255', true],
	['169.255.0.0', false],
	// Not private for THIS gate (special-use, but handled by isGloballyRoutableIp)
	['0.0.0.0', false],
	['0.255.255.255', false],
	['100.64.0.1', false],
	['100.127.255.255', false],
	['192.0.0.1', false],
	['192.0.2.1', false],
	['192.88.99.1', false],
	['198.18.0.1', false],
	['198.19.255.255', false],
	['198.51.100.1', false],
	['203.0.113.1', false],
	['224.0.0.1', false],
	['240.0.0.1', false],
	['255.255.255.255', false],
	['1.1.1.1', false],
	['8.8.8.8', false],
	// Leading zeros are accepted by isValidIPv4 and read as decimal
	['010.0.0.1', true],
	['10.0.0.001', true],
	['127.0.0.01', true],
	['172.016.0.1', true],
	['0127.0.0.1', false], // four digits: not a valid octet
];

const IPV6_BOUNDARIES: Array<[string, boolean]> = [
	// loopback is matched by exact string only
	['::1', true],
	['::1 ', false],
	['::2', false],
	['::', false],
	['0:0:0:0:0:0:0:1', false],
	['0000:0000:0000:0000:0000:0000:0000:0001', false],
	['::1%lo', false],
	// link-local is matched by the literal `fe80:` prefix only (not the full fe80::/10)
	['fe7f::1', false],
	['fe80::', true],
	['fe80::1', true],
	['FE80::1', true],
	['fe80:0:0:0:0:0:0:1', true],
	['fe80::1%eth0', true],
	['fe80:', true],
	['fe81::1', false],
	['febf::1', false],
	['fec0::1', false],
	['fe80', false], // no colon: takes the IPv4 path and is invalid there
	// ULA fc00::/7 is matched by a `fc` / `fd` prefix
	['fbff:ffff::1', false],
	['fc00::', true],
	['fc00::1', true],
	['FC00::1', true],
	['fcff:ffff::1', true],
	['fd00::1', true],
	['FD12:3456::1', true],
	['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
	['fe00::1', false],
	['ff02::1', false],
	['fc:', true], // prefix match only: shorter-than-a-group strings still match
	['fc.example:80', true], // current prefix-match quirk, pinned
	// Public and special-use IPv6 are not private for this gate
	['2606:4700:4700::1111', false],
	['2001:db8::1', false],
	['64:ff9b::1', false],
	['2002::1', false],
	['ff00::', false],
	// IPv4-mapped forms are NOT unwrapped by this gate
	['::ffff:10.0.0.1', false],
	['::ffff:127.0.0.1', false],
	['::ffff:192.168.1.1', false],
	['::ffff:a00:1', false],
];

const MALFORMED_V4: string[] = [
	'',
	' ',
	'10',
	'10.0.0',
	'10.0.0.0.1',
	'10.0.0.256',
	'256.0.0.1',
	'-10.0.0.1',
	'10.0.0.-1',
	' 10.0.0.1',
	'10.0.0.1 ',
	'10.0.0.1\n',
	'10.0.0.',
	'.10.0.0.1',
	'10..0.1',
	'10.0.0.a',
	'0x0a.0.0.1',
	'10.0.0.1%eth0',
	'1e1.0.0.1',
	'192.168.1',
	'fd',
	'localhost',
];

describe('isPrivateIP boundaries', () => {
	it.each(IPV4_BOUNDARIES)('IPv4 %s private=%s', async (address, expected) => {
		const { isPrivateIP } = await import('../src/lib/ip-utils');
		expect(isPrivateIP(address), address).toBe(expected);
	});

	it.each(IPV6_BOUNDARIES)('IPv6 %j private=%s', async (address, expected) => {
		const { isPrivateIP } = await import('../src/lib/ip-utils');
		expect(isPrivateIP(address), address).toBe(expected);
	});

	it.each(MALFORMED_V4)('treats malformed non-IPv6 input %j as not private', async (address) => {
		const { isPrivateIP } = await import('../src/lib/ip-utils');
		expect(isPrivateIP(address)).toBe(false);
	});

	it('matches an independent arithmetic oracle across the IPv4 grid', async () => {
		const { isPrivateIP } = await import('../src/lib/ip-utils');
		const blocked: Array<[number, number]> = [
			[0x0a000000, 0x0affffff],
			[0x7f000000, 0x7fffffff],
			[0xa9fe0000, 0xa9feffff],
			[0xac100000, 0xac1fffff],
			[0xc0a80000, 0xc0a8ffff],
		];
		for (let a = 0; a < 256; a += 1) {
			for (let b = 0; b < 256; b += 1) {
				for (const c of [0, 1, 255]) {
					for (const d of [0, 1, 255]) {
						const value = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
						const expected = blocked.some(([lo, hi]) => value >= lo && value <= hi);
						const text = `${a}.${b}.${c}.${d}`;
						if (isPrivateIP(text) !== expected) throw new Error(`verdict mismatch for ${text}`);
					}
				}
			}
		}
	});
});
