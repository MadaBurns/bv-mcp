// SPDX-License-Identifier: BUSL-1.1

/**
 * Exhaustive boundary pin for `isGloballyRoutableIp` (SSRF gate for raw-socket destinations).
 *
 * For every special-use range, in both families: the first address, the last address, one
 * below and one above. Verdicts are written out by hand from the range definitions and were
 * verified to pass on the pre-refactor implementation, so this spec pins identical behaviour
 * across the range-table refactor.
 */
import { describe, expect, it } from 'vitest';

// [address, routable]. Rows come in groups: below, first, last, above.
const IPV4_BOUNDARIES: Array<[string, boolean]> = [
	// 0.0.0.0/8 (the range starts at the bottom of the space: no "below")
	['0.0.0.0', false],
	['0.255.255.255', false],
	['1.0.0.0', true],
	// 10.0.0.0/8
	['9.255.255.255', true],
	['10.0.0.0', false],
	['10.255.255.255', false],
	['11.0.0.0', true],
	// 100.64.0.0/10 (CGNAT shared address space)
	['100.63.255.255', true],
	['100.64.0.0', false],
	['100.127.255.255', false],
	['100.128.0.0', true],
	// 127.0.0.0/8 loopback
	['126.255.255.255', true],
	['127.0.0.0', false],
	['127.255.255.255', false],
	['128.0.0.0', true],
	// 169.254.0.0/16 link-local
	['169.253.255.255', true],
	['169.254.0.0', false],
	['169.254.255.255', false],
	['169.255.0.0', true],
	// 172.16.0.0/12
	['172.15.255.255', true],
	['172.16.0.0', false],
	['172.31.255.255', false],
	['172.32.0.0', true],
	// 192.0.0.0/24 IETF protocol assignments
	['191.255.255.255', true],
	['192.0.0.0', false],
	['192.0.0.255', false],
	['192.0.1.0', true],
	// 192.0.2.0/24 TEST-NET-1
	['192.0.1.255', true],
	['192.0.2.0', false],
	['192.0.2.255', false],
	['192.0.3.0', true],
	// 192.88.99.0/24 deprecated 6to4 relay anycast
	['192.88.98.255', true],
	['192.88.99.0', false],
	['192.88.99.255', false],
	['192.88.100.0', true],
	// 192.168.0.0/16
	['192.167.255.255', true],
	['192.168.0.0', false],
	['192.168.255.255', false],
	['192.169.0.0', true],
	// 198.18.0.0/15 benchmarking
	['198.17.255.255', true],
	['198.18.0.0', false],
	['198.19.255.255', false],
	['198.20.0.0', true],
	// 198.51.100.0/24 TEST-NET-2
	['198.51.99.255', true],
	['198.51.100.0', false],
	['198.51.100.255', false],
	['198.51.101.0', true],
	// 203.0.113.0/24 TEST-NET-3
	['203.0.112.255', true],
	['203.0.113.0', false],
	['203.0.113.255', false],
	['203.0.114.0', true],
	// 224.0.0.0/3 multicast + reserved + limited broadcast (runs to the top of the space)
	['223.255.255.255', true],
	['224.0.0.0', false],
	['239.255.255.255', false],
	['240.0.0.0', false],
	['255.255.255.255', false],
	// Ordinary public unicast, including the octet extremes of the allowed space
	['1.1.1.1', true],
	['8.8.8.8', true],
	['223.0.0.1', true],
	['1.0.0.0', true],
];

const IPV6_BOUNDARIES: Array<[string, boolean]> = [
	// Everything below the 2000::/3 global-unicast allocation
	['::', false],
	['::1', false],
	['::2', false],
	['1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', false],
	// 2000::/3 first and last, then above it
	['2000::', true],
	['2000:0:0:0:0:0:0:1', true],
	['3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
	['3fff::', true],
	['4000::', false],
	['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', false],
	// 2001::/23 IETF special-purpose space (2001:0000 .. 2001:01ff)
	['2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
	['2001::', false],
	['2001:0:0:0:0:0:0:1', false],
	['2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff', false],
	['2001:200::', true],
	// 2001:db8::/32 documentation
	['2001:db7:ffff:ffff:ffff:ffff:ffff:ffff', true],
	['2001:db8::', false],
	['2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', false],
	['2001:db9::', true],
	['2001:DB8::1', false],
	// 2002::/16 deprecated 6to4
	['2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
	['2002::', false],
	['2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff', false],
	['2003::', true],
	// 3ffe::/16 deprecated 6bone
	['3ffd:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
	['3ffe::', false],
	['3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff', false],
	// ordinary public unicast
	['2606:4700:4700::1111', true],
	['2606:4700:4700:0:0:0:0:1111', true],
	['2a00:1450:4009:81f::200e', true],
	['2606:4700::A', true],
	// Embedded-IPv4 and transition forms that sit outside 2000::/3 (or inside a blocked block)
	['::ffff:1.2.3.4', false],
	['::ffff:0:0', false],
	['::ffff:7f00:1', false],
	['64:ff9b::1.2.3.4', false],
	['64:ff9b::102:304', false],
	['2001:0:4136:e378:8000:63bf:3fff:fdd2', false], // Teredo, inside 2001::/23
	['2002:102:304::1', false], // 6to4, inside 2002::/16
	['fe80::1', false],
	['fc00::1', false],
	['fd00::1', false],
	['ff02::1', false],
	// A trailing dotted-quad is accepted in the last position only
	['2606:4700::1.2.3.4', true],
];

const MALFORMED: string[] = [
	'',
	' ',
	'.',
	':',
	'1',
	'1.2.3',
	'1.2.3.4.5',
	'1.2.3.',
	'.1.2.3.4',
	'1..2.3',
	'256.1.1.1',
	'1.1.1.256',
	'999.999.999.999',
	'-1.1.1.1',
	'1.1.1.-1',
	'1.1.1.1 ',
	' 1.1.1.1',
	'1.1.1.1\n',
	'0x1.1.1.1',
	'1.1.1.a',
	'01.1.1.1', // leading zero
	'1.1.1.01',
	'1.1.1.001',
	'1.1.1.1%eth0', // zone id on a v4 literal
	'1.1.1.1:53',
	'::::',
	':::',
	'1::2::3',
	'2606:4700:4700::1111:',
	':2606:4700:4700::1111',
	'12345::',
	'g::',
	'2606:4700:4700:0:0:0:0:0:1', // nine groups
	'2606:4700:4700:0:0:0:0', // seven groups, no compression
	'1:2:3:4:5:6:7::8', // `::` that compresses nothing
	'2606:4700::1.2.3', // short dotted quad
	'2606:4700::1.2.3.4:5', // dotted quad not last
	'2606:4700::1.2.3.04', // leading zero in embedded v4
	'2606:4700::1.2.3.256',
	'2606:4700::1111%eth0', // zone id
	'fe80::1%eth0',
	'[2606:4700::1111]',
	'2606:4700:4700::1111/64',
];

describe('isGloballyRoutableIp boundaries', () => {
	it.each(IPV4_BOUNDARIES)('IPv4 %s routable=%s', async (address, routable) => {
		const { isGloballyRoutableIp } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		expect(isGloballyRoutableIp(address), address).toBe(routable);
	});

	it.each(IPV6_BOUNDARIES)('IPv6 %s routable=%s', async (address, routable) => {
		const { isGloballyRoutableIp } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		expect(isGloballyRoutableIp(address), address).toBe(routable);
	});

	it.each(MALFORMED)('rejects malformed input %j', async (address) => {
		const { isGloballyRoutableIp } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		expect(isGloballyRoutableIp(address)).toBe(false);
	});

	it('is a pure total function over the whole IPv4 /8 grid (a.b.0.1 verdicts match the range definitions)', async () => {
		const { isGloballyRoutableIp } = await import('../src/lib/authoritative-dns-infra/dns-tcp');
		// Independent oracle written as plain arithmetic ranges (no shared code with the module).
		const blocked: Array<[number, number]> = [
			[0x00000000, 0x00ffffff],
			[0x0a000000, 0x0affffff],
			[0x64400000, 0x647fffff],
			[0x7f000000, 0x7fffffff],
			[0xa9fe0000, 0xa9feffff],
			[0xac100000, 0xac1fffff],
			[0xc0000000, 0xc00000ff],
			[0xc0000200, 0xc00002ff],
			[0xc0586300, 0xc05863ff],
			[0xc0a80000, 0xc0a8ffff],
			[0xc6120000, 0xc613ffff],
			[0xc6336400, 0xc63364ff],
			[0xcb007100, 0xcb0071ff],
			[0xe0000000, 0xffffffff],
		];
		for (let a = 0; a < 256; a += 1) {
			for (let b = 0; b < 256; b += 1) {
				for (const c of [0, 1, 2, 99, 100, 113, 255]) {
					for (const d of [0, 1, 255]) {
						const value = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
						const expected = !blocked.some(([lo, hi]) => value >= lo && value <= hi);
						const text = `${a}.${b}.${c}.${d}`;
						if (isGloballyRoutableIp(text) !== expected) throw new Error(`verdict mismatch for ${text}`);
					}
				}
			}
		}
	});
});
