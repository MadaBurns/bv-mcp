// SPDX-License-Identifier: BUSL-1.1

/**
 * Validate a dotted-decimal IPv4 address.
 * Requires exactly four decimal octets in the 0-255 range with no surrounding
 * whitespace or shorthand forms.
 */
export function isValidIPv4(ip: string): boolean {
	const parts = ip.split('.');
	if (parts.length !== 4) return false;

	return parts.every((part) => {
		if (!/^\d{1,3}$/.test(part)) return false;
		const value = Number(part);
		return Number.isInteger(value) && value >= 0 && value <= 255;
	});
}

/**
 * Reverse the octets of an IPv4 address.
 * Used for DNSBL and PTR queries (e.g., "192.0.2.1" to "1.2.0.192").
 */
export function reverseIPv4(ip: string): string {
	return ip.split('.').reverse().join('.');
}

/**
 * Expand a possibly-compressed IPv6 address to its full 32-nibble form,
 * reverse the nibbles, and join with dots.
 * Used for Cymru ASN lookups and ip6.arpa PTR queries.
 *
 * @example reverseIPv6("2001:0db8::1") returns the nibble-reversed ip6.arpa label.
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

/** A special-use prefix over the leading 32 bits of an address: network value + prefix length (1-32). */
export interface Prefix32 {
	net: number;
	len: number;
}

/** True when the top `len` bits of `value` (an unsigned 32-bit integer) equal those of `net`. */
export function matchesPrefix32(value: number, { net, len }: Prefix32): boolean {
	return value >>> (32 - len) === net >>> (32 - len);
}

/** IPv4 ranges treated as private by isPrivateIP: RFC 1918, loopback and link-local only. */
const PRIVATE_IPV4_PREFIXES: readonly Prefix32[] = [
	{ net: 0x0a000000, len: 8 }, // 10.0.0.0/8
	{ net: 0xac100000, len: 12 }, // 172.16.0.0/12
	{ net: 0xc0a80000, len: 16 }, // 192.168.0.0/16
	{ net: 0x7f000000, len: 8 }, // 127.0.0.0/8 (loopback)
	{ net: 0xa9fe0000, len: 16 }, // 169.254.0.0/16 (link-local)
];

/** IPv6 is matched textually (exact loopback, then lowercase literal prefixes), not by parsed bits. */
function isPrivateIPv6Text(ip: string): boolean {
	if (ip === '::1') return true;
	const lower = ip.toLowerCase();
	// Link-local fe80::/10 (literal `fe80:` prefix) and ULA fc00::/7 (first byte fc or fd, binary 1111110x)
	return lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd');
}

/**
 * Check whether an IP address is in a private/reserved range.
 * Covers RFC 1918, loopback, link-local, and IPv6 ULA.
 */
export function isPrivateIP(ip: string): boolean {
	if (ip.includes(':')) return isPrivateIPv6Text(ip);

	if (!isValidIPv4(ip)) return false;
	const [a, b, c, d] = ip.split('.').map(Number);
	const value = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
	return PRIVATE_IPV4_PREFIXES.some((prefix) => matchesPrefix32(value, prefix));
}
