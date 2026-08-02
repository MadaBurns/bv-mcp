// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM key analysis helpers.
 * Pure functions for analyzing DKIM key strength and consolidating findings.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

export type DkimKeyStrength = 'critical' | 'high' | 'medium' | 'info';

export type DkimKeyAnalysis = {
	bits: number | null;
	strength: DkimKeyStrength;
	keyType: 'rsa' | 'ed25519' | 'unknown' | 'rsa-malformed';
};

/**
 * Canonical SubjectPublicKeyInfo DER prefixes (base64) that identify the declared RSA
 * modulus size. These bytes precede the modulus, so they survive truncation: a key whose
 * data is cut short — or split across multiple TXT RRs (RFC 6376 §3.6.2 violation), so the
 * resolver returns only a fragment — still carries its declared-size header. `fullChars` is
 * the base64 length of a *complete* key of that size (deterministic for DER).
 */
const RSA_SPKI_HEADERS: ReadonlyArray<{ prefix: string; bits: number; fullChars: number }> = [
	{ prefix: 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBA', bits: 512, fullChars: 128 },
	{ prefix: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB', bits: 1024, fullChars: 216 },
	{ prefix: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A', bits: 2048, fullChars: 392 },
	{ prefix: 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A', bits: 4096, fullChars: 736 },
];

/**
 * Parsed RFC 6376 §3.6.1 `t=` flag list (colon-separated).
 *
 * Parsing goes through {@link getDkimTagValue} rather than a bare `/t=y/` scan so that
 * (a) flags declared in any order are seen (`t=s:y` is as valid as `t=y:s`),
 * (b) surrounding whitespace (`; t = y ;`) does not hide the flag, and
 * (c) a `t=y` substring inside another tag's value (notably the free-text `n=` notes
 *     tag) cannot manufacture a phantom test-mode finding.
 */
export type DkimFlags = {
	/** `t=y` — test mode. Verifiers are told to treat a failure as if DKIM were not deployed. */
	testMode: boolean;
	/** `t=s` — strict mode: the signature's `i=` domain must not be a subdomain of `d=`. */
	strictSubdomain: boolean;
	/** Every parsed flag token, lowercased (unknown flags included; RFC 6376 says ignore them). */
	flags: string[];
};

/** Parse the DKIM `t=` flag list from a record. Absent/empty `t=` yields all-false. */
export function parseDkimFlags(record: string): DkimFlags {
	const raw = getDkimTagValue(record, 't');
	const flags = raw
		? raw
				.split(':')
				.map((f) => f.trim().toLowerCase())
				.filter(Boolean)
		: [];
	return { testMode: flags.includes('y'), strictSubdomain: flags.includes('s'), flags };
}

/**
 * Classification of an `h=` (acceptable hash algorithms) restriction, per RFC 8301.
 *
 * - `sha1-only`     — sha1 listed, sha256 absent. RFC 8301 §3.1: rsa-sha1 MUST NOT be used and
 *                     such signatures "have permanently failed evaluation" — the key cannot
 *                     verify a conforming signature at all.
 * - `no-sha256`     — the restriction lists neither sha256 nor sha1 (e.g. `h=sha512`). sha256 is
 *                     the only mandatory-to-implement hash (RFC 8301 §3.2), so a signer/verifier
 *                     pair using it is turned away by the key record.
 * - `sha1-permitted`— sha256 IS listed but sha1 is listed alongside it. The key still verifies
 *                     modern signatures, but it also advertises acceptance of a hash RFC 8301
 *                     prohibits, leaving a downgrade surface for a forged sha1 signature.
 */
export type DkimHashRestriction = {
	algorithms: string[];
	kind: 'sha1-only' | 'no-sha256' | 'sha1-permitted';
};

/** Classify a record's `h=` restriction, or `null` when `h=` is absent, empty, or healthy. */
export function analyzeHashRestriction(record: string): DkimHashRestriction | null {
	const raw = getDkimTagValue(record, 'h');
	if (!raw) return null;
	const algorithms = raw
		.split(':')
		.map((h) => h.trim().toLowerCase())
		.filter(Boolean);
	if (algorithms.length === 0) return null;

	const hasSha256 = algorithms.includes('sha256');
	const hasSha1 = algorithms.includes('sha1');
	if (!hasSha256) return { algorithms, kind: hasSha1 ? 'sha1-only' : 'no-sha256' };
	if (hasSha1) return { algorithms, kind: 'sha1-permitted' };
	return null;
}

/** Parsed RFC 6376 §3.6.1 `s=` service-type list. */
export type DkimServiceTypes = {
	services: string[];
	/** True when the list admits email — i.e. contains `email` or the `*` wildcard. */
	coversEmail: boolean;
};

/**
 * Parse the `s=` service-type restriction. Returns `null` when `s=` is absent or empty
 * (both mean the `*` default, which covers email).
 *
 * RFC 6376 §6.1.2 requires a verifier to ignore a key record whose service-type list does
 * not admit email — so a mistyped or over-narrow `s=` silently disables the selector for
 * mail while leaving a perfectly well-formed-looking record published in DNS.
 */
export function analyzeServiceTypes(record: string): DkimServiceTypes | null {
	const raw = getDkimTagValue(record, 's');
	if (!raw) return null;
	const services = raw
		.split(':')
		.map((s) => s.trim().toLowerCase())
		.filter(Boolean);
	if (services.length === 0) return null;
	return { services, coversEmail: services.includes('*') || services.includes('email') };
}

export function getDkimTagValue(record: string, tag: string): string | undefined {
	if (!/^[a-zA-Z0-9]+$/.test(tag)) return undefined;
	// `\s*` on BOTH sides of the `=`: RFC 6376 §3.2 defines `tag-spec = [FWS] tag-name [FWS]
	// "=" [FWS] tag-value [FWS]`, so folding whitespace around the equals sign is valid and
	// `t = y` / `p = <key>` must parse. Requiring a bare `tag=` silently returned undefined
	// for every tag on such a record — for `p=` that reads as "no key material".
	// nosemgrep: detect-non-literal-regexp -- `tag` is guarded to /^[a-zA-Z0-9]+$/ above (no metachars);
	// pattern has no nested quantifiers, so it is linear-time (verified <2ms @ 500K chars). Not ReDoS.
	const match = record.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=([^;]*)`, 'i'));
	return match?.[1]?.trim();
}

/**
 * Analyze key strength based on key type and base64 character count.
 * For RSA keys, estimates bit-length from base64 character count.
 * For Ed25519 keys, always returns info (strong by design).
 */
export function analyzeKeyStrength(publicKeyBase64: string | undefined, declaredKeyType: string): DkimKeyAnalysis {
	if (!publicKeyBase64) {
		return { bits: null, strength: 'info', keyType: 'unknown' };
	}

	if (declaredKeyType === 'ed25519') {
		return { bits: 256, strength: 'info', keyType: 'ed25519' };
	}

	const cleanKey = publicKeyBase64.replace(/\s/g, '');
	const charCount = cleanKey.length;

	// Determine the declared modulus size from the DER header when recognizable. This is
	// authoritative and survives truncation, so it stops a truncated or fragmented key (e.g.
	// a 2048-bit key split across multiple TXT records, where the resolver returns only a
	// short fragment) from being mis-measured as a weak short key by the char-count heuristic.
	const header = RSA_SPKI_HEADERS.find((h) => cleanKey.startsWith(h.prefix));
	if (header) {
		// A complete key of this size has ~fullChars base64 chars. Real truncations seen in
		// the wild are short fragments (≤60% of full); requiring <70% flags those as malformed
		// — rather than inventing a small bit-count and escalating to a false "weak key"
		// critical — while leaving near-complete keys to the normal strength mapping.
		if (charCount < header.fullChars * 0.7) {
			return { bits: header.bits, strength: 'medium', keyType: 'rsa-malformed' };
		}
		if (header.bits <= 512) return { bits: 512, strength: 'critical', keyType: 'rsa' };
		if (header.bits <= 1024) return { bits: 1024, strength: 'high', keyType: 'rsa' };
		if (header.bits < 2048) return { bits: header.bits, strength: 'medium', keyType: 'rsa' };
		return { bits: header.bits, strength: 'info', keyType: 'rsa' };
	}

	if (declaredKeyType === 'rsa-default' && charCount < 50) {
		return { bits: null, strength: 'medium', keyType: 'unknown' };
	}

	if (charCount < 150) {
		return { bits: 512, strength: 'critical', keyType: 'rsa' };
	}

	if (charCount < 230) {
		return { bits: 1024, strength: 'high', keyType: 'rsa' };
	}

	if (charCount < 350) {
		return { bits: 2048, strength: 'medium', keyType: 'rsa' };
	}

	// 2048-bit RSA keys: PKCS#1 format ~355 chars, SubjectPublicKeyInfo ~392 chars.
	// Threshold at 350 safely covers both encodings without false-positives.
	if (charCount < 550) {
		return { bits: 2048, strength: 'info', keyType: 'rsa' };
	}

	return { bits: 4096, strength: 'info', keyType: 'rsa' };
}

export function consolidateSelectorProbeKeyStrengthFindings(findings: Finding[]): void {
	const seen = new Set<string>();
	let removed = 0;

	for (let index = findings.length - 1; index >= 0; index--) {
		const finding = findings[index];
		if (!/rsa key:/i.test(finding.title)) continue;
		if (!['critical', 'high', 'medium'].includes(finding.severity)) continue;
		const estimatedBits = finding.metadata?.estimatedBits;
		const keyType = finding.metadata?.keyType;
		if (typeof estimatedBits !== 'number' || keyType !== 'rsa') continue;

		const key = `${finding.severity}:${estimatedBits}:${keyType}`;
		if (seen.has(key)) {
			findings.splice(index, 1);
			removed += 1;
			continue;
		}

		seen.add(key);
	}

	if (removed > 0) {
		findings.push(
			createFinding(
				'dkim',
				'Similar DKIM key-strength findings consolidated',
				'info',
				`Consolidated ${removed} duplicate selector-probe key-strength finding(s) to reduce repeated penalty for identical key profiles across selectors.`,
			),
		);
	}
}
