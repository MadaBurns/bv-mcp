// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';

describe('ip-utils', () => {
	describe('reverseIPv4', () => {
		it('reverses simple octets', async () => {
			const { reverseIPv4 } = await import('../src/lib/ip-utils');
			expect(reverseIPv4('1.2.3.4')).toBe('4.3.2.1');
		});

		it('reverses a public IP', async () => {
			const { reverseIPv4 } = await import('../src/lib/ip-utils');
			expect(reverseIPv4('198.51.100.25')).toBe('25.100.51.198');
		});

		it('reverses loopback', async () => {
			const { reverseIPv4 } = await import('../src/lib/ip-utils');
			expect(reverseIPv4('127.0.0.1')).toBe('1.0.0.127');
		});
	});

	describe('reverseIPv6', () => {
		it('reverses a compressed IPv6 address', async () => {
			const { reverseIPv6 } = await import('../src/lib/ip-utils');
			expect(reverseIPv6('2001:0db8::1')).toBe(
				'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2',
			);
		});

		it('reverses a fully expanded IPv6 address', async () => {
			const { reverseIPv6 } = await import('../src/lib/ip-utils');
			expect(reverseIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(
				'4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2',
			);
		});

		it('reverses ::1 (loopback)', async () => {
			const { reverseIPv6 } = await import('../src/lib/ip-utils');
			expect(reverseIPv6('::1')).toBe(
				'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0',
			);
		});

		it('reverses :: (all zeros)', async () => {
			const { reverseIPv6 } = await import('../src/lib/ip-utils');
			expect(reverseIPv6('::')).toBe(
				'0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0',
			);
		});

		it('reverses fe80::1 (link-local)', async () => {
			const { reverseIPv6 } = await import('../src/lib/ip-utils');
			// fe80:0000:0000:0000:0000:0000:0000:0001 → nibbles reversed
			expect(reverseIPv6('fe80::1')).toBe(
				'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f',
			);
		});
	});

	describe('isPrivateIP', () => {
		// RFC 1918 ranges
		it('detects 10.x.x.x as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('10.0.0.1')).toBe(true);
			expect(isPrivateIP('10.255.255.255')).toBe(true);
		});

		it('detects 172.16-31.x.x as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('172.16.0.1')).toBe(true);
			expect(isPrivateIP('172.31.255.255')).toBe(true);
			expect(isPrivateIP('172.15.0.1')).toBe(false);
			expect(isPrivateIP('172.32.0.1')).toBe(false);
		});

		it('detects 192.168.x.x as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('192.168.0.1')).toBe(true);
			expect(isPrivateIP('192.168.255.255')).toBe(true);
		});

		// Loopback
		it('detects IPv4 loopback as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('127.0.0.1')).toBe(true);
			expect(isPrivateIP('127.255.255.255')).toBe(true);
		});

		it('detects IPv6 loopback as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('::1')).toBe(true);
		});

		// Link-local
		it('detects IPv4 link-local as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('169.254.1.1')).toBe(true);
		});

		it('detects IPv6 link-local as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('fe80::1')).toBe(true);
		});

		// ULA (fc00::/7 = fc00:: through fdff::)
		it('detects IPv6 ULA as private', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('fd00::1')).toBe(true);
			expect(isPrivateIP('fc00::1')).toBe(true);
		});

		// Public IPs should return false
		it('returns false for public IPv4', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('8.8.8.8')).toBe(false);
			expect(isPrivateIP('1.1.1.1')).toBe(false);
			expect(isPrivateIP('198.51.100.25')).toBe(false);
		});

		it('returns false for public IPv6', async () => {
			const { isPrivateIP } = await import('../src/lib/ip-utils');
			expect(isPrivateIP('2001:4860:4860::8888')).toBe(false);
			expect(isPrivateIP('2606:4700:4700::1111')).toBe(false);
		});
	});
});
