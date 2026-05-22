import { describe, it, expect } from 'vitest';
import { normalizeProvider, groupByProvider, isMultiProvider } from '../src/lib/brand-audit-provider-sprawl';

describe('normalizeProvider', () => {
	it('collapses awsdns-N.{com,net,co.uk} → "AWS Route 53"', () => {
		expect(normalizeProvider('ns-52.awsdns-52.com')).toBe('AWS Route 53');
		expect(normalizeProvider('ns-1234.awsdns-43.co.uk')).toBe('AWS Route 53');
		expect(normalizeProvider('ns-2002.awsdns-24.net')).toBe('AWS Route 53');
	});
	it('collapses *.ultradns.{net,com,org,biz} → "UltraDNS (Vercara)"', () => {
		expect(normalizeProvider('pdns1.ultradns.net')).toBe('UltraDNS (Vercara)');
		expect(normalizeProvider('pdns2.ultradns.com')).toBe('UltraDNS (Vercara)');
		expect(normalizeProvider('pdns3.ultradns.org')).toBe('UltraDNS (Vercara)');
	});
	it('identifies Cloudflare, NS1, Akamai, MarkMonitor, Google, Apple', () => {
		expect(normalizeProvider('zara.ns.cloudflare.com')).toBe('Cloudflare');
		expect(normalizeProvider('p08.nsone.net')).toBe('NS1');
		expect(normalizeProvider('a1-21.akam.net')).toBe('Akamai');
		expect(normalizeProvider('ns1.markmonitor.com')).toBe('MarkMonitor');
		expect(normalizeProvider('ns1.google.com')).toBe('Google (in-house)');
		expect(normalizeProvider('a.ns.apple.com')).toBe('Apple (in-house)');
	});
	it('falls back to apex-2 label for unknown providers', () => {
		expect(normalizeProvider('ns1.weirdhost.example')).toBe('weirdhost.example');
	});
	it('handles empty/invalid input without throwing', () => {
		expect(normalizeProvider('')).toBe('unknown');
		expect(normalizeProvider('.')).toBe('unknown');
	});
});

describe('groupByProvider', () => {
	it('collapses fragmented AWS NS to one provider count', () => {
		expect(groupByProvider(['ns-52.awsdns-52.com', 'ns-1234.awsdns-43.co.uk', 'ns-2002.awsdns-24.net'])).toEqual({
			'AWS Route 53': 3,
		});
	});
	it('returns multiple providers when NS list crosses orgs', () => {
		expect(groupByProvider(['a.ns.paypal.com', 'b.ns.paypal.com', 'pdns1.ultradns.net', 'pdns2.ultradns.com'])).toEqual({
			'paypal.com': 2,
			'UltraDNS (Vercara)': 2,
		});
	});
	it('deduplicates duplicate nameservers within input', () => {
		expect(groupByProvider(['ns1.cloudflare.com', 'ns1.cloudflare.com'])).toEqual({ Cloudflare: 1 });
	});
});

describe('isMultiProvider', () => {
	it('returns false for single-provider AWS spread', () => {
		expect(isMultiProvider(['ns-52.awsdns-52.com', 'ns-1234.awsdns-43.co.uk'])).toBe(false);
	});
	it('returns true for paypal-style UltraDNS + in-house', () => {
		expect(isMultiProvider(['pdns1.ultradns.net', 'pdns2.ultradns.com', 'a.ns.paypal.com', 'b.ns.paypal.com'])).toBe(true);
	});
	it('returns false for single-provider list', () => {
		expect(isMultiProvider(['ns1.google.com', 'ns2.google.com', 'ns3.google.com'])).toBe(false);
	});
	it('returns false for empty / single-NS list', () => {
		expect(isMultiProvider([])).toBe(false);
		expect(isMultiProvider(['ns1.google.com'])).toBe(false);
	});
});
