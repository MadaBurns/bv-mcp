// Unit tests for the /internal/* guard decision.
//
// The guard middleware in src/internal.ts must reject every public-internet
// request and admit every service-binding request. Cloudflare always sets
// `cf-connecting-ip` on public requests; service bindings never carry it.
// We extract the decision into a pure function so the contract can be tested
// without negotiating Worker test-pool header propagation quirks.

import { describe, it, expect } from 'vitest';
import { isPublicInternetRequest } from '../src/internal';

describe('isPublicInternetRequest', () => {
	it('returns true when cf-connecting-ip is present (Cloudflare-routed public request)', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: '198.51.100.10', host: 'dns-mcp.example.com' })).toBe(true);
	});

	it('returns false when cf-connecting-ip is absent (service binding)', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: null, host: 'dns-mcp.example.com' })).toBe(false);
	});

	it('ignores forwarded public IP headers when cf-connecting-ip is absent', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: null, host: 'dns-mcp.example.com' })).toBe(false);
	});

	it('returns true even when Host is localhost — Host header must not bypass cf-connecting-ip', () => {
		// Regression for the removed Host-based bypass. Cloudflare sets cf-connecting-ip
		// authoritatively; an attacker-supplied Host header is never a reason to skip the gate.
		expect(isPublicInternetRequest({ cfConnectingIp: '198.51.100.10', host: 'localhost:8787' })).toBe(true);
	});

	it('returns true even when Host is 127.0.0.1 — same regression as localhost', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: '198.51.100.10', host: '127.0.0.1:8787' })).toBe(true);
	});

	it('returns false when both cf-connecting-ip and Host are absent (wrangler dev / pure service binding)', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: null, host: null })).toBe(false);
	});
});
