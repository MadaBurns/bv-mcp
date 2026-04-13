// SPDX-License-Identifier: BUSL-1.1

/**
 * Reverse the octets of an IPv4 address.
 * Used for DNSBL and PTR queries (e.g., "1.2.3.4" → "4.3.2.1").
 */
export function reverseIPv4(ip: string): string {
	return ip.split('.').reverse().join('.');
}

/**
 * Expand a possibly-compressed IPv6 address to its full 32-nibble form,
 * reverse the nibbles, and join with dots.
 * Used for Cymru ASN lookups and ip6.arpa PTR queries.
 *
 * @example reverseIPv6("2001:0db8::1") → "1.0.0.0...8.b.d.0.1.0.0.2"
 */
export function reverseIPv6(ip: string): string {
	// Expand :: shorthand to full 8 groups
	const halves = ip.split('::');
	let groups: string[];

	if (halves.length === 2) {
		const left = halves[0] ? halves[0].split(':') : [];
		const right = halves[1] ? halves[1].split(':') : [];
		const missing = 8 - left.length - right.length;
		groups = [...left, ...Array(missing).fill('0000'), ...right];
	} else {
		groups = ip.split(':');
	}

	// Pad each group to 4 hex digits, concatenate all 32 nibbles, reverse, dot-join
	const nibbles = groups.map((g) => g.padStart(4, '0')).join('');
	return nibbles.split('').reverse().join('.');
}

/**
 * Check whether an IP address is in a private/reserved range.
 * Covers RFC 1918, loopback, link-local, and IPv6 ULA.
 */
export function isPrivateIP(ip: string): boolean {
	// IPv6 check
	if (ip.includes(':')) {
		if (ip === '::1') return true;
		const lower = ip.toLowerCase();
		// Link-local fe80::/10
		if (lower.startsWith('fe80:')) return true;
		// ULA fc00::/7 — first byte is fc or fd (binary 1111110x)
		if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
		return false;
	}

	// IPv4 check
	const parts = ip.split('.').map(Number);
	if (parts.length !== 4) return false;

	const [a, b] = parts;
	// 10.0.0.0/8
	if (a === 10) return true;
	// 172.16.0.0/12
	if (a === 172 && b >= 16 && b <= 31) return true;
	// 192.168.0.0/16
	if (a === 192 && b === 168) return true;
	// 127.0.0.0/8 (loopback)
	if (a === 127) return true;
	// 169.254.0.0/16 (link-local)
	if (a === 169 && b === 254) return true;

	return false;
}
