// SPDX-License-Identifier: BUSL-1.1

/**
 * SVCB/HTTPS DNS record check (RFC 9460).
 * Queries HTTPS resource records at the apex domain and validates the
 * presence and content of modern transport capability advertisements.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';

/**
 * Parse ALPN protocols from an HTTPS record data string (presentation format).
 */
function parseAlpn(data: string): string[] {
	const match = data.match(/\balpn=(?:"([^"]+)"|(\S+))/i);
	if (!match) return [];
	const raw = match[1] ?? match[2] ?? '';
	return raw.split(',').map((p) => p.trim()).filter(Boolean);
}

/**
 * Check for ECH (Encrypted Client Hello) in the HTTPS record data (presentation format).
 */
function hasEch(data: string): boolean {
	return /\bech=/i.test(data);
}

/**
 * Parse the priority from HTTPS record data (presentation format).
 */
function parsePriority(data: string): number | null {
	const match = data.match(/^(\d+)\s/);
	if (!match) return null;
	return parseInt(match[1], 10);
}

/** True when `data` starts with the RFC 3597 unknown-RR marker (`\#`, or a bare `#`). */
function hasWirePrefix(data: string): boolean {
	return data.startsWith('\\#') || data.startsWith('#');
}

function isWirePrefixToken(token: string): boolean {
	return token === '\\#' || token === '#';
}

/** A usable rdata length: finite, and at least the 2-byte priority plus a 1-byte root TargetName. */
function isUsableWireLength(declaredLen: number): boolean {
	return Number.isFinite(declaredLen) && declaredLen >= 3;
}

/**
 * Split `\# <length> <hex bytes>` into its declared length and joined hex digits.
 * Returns null if `data` is not in wire format or the declared length is unusable.
 */
function splitWireTokens(data: string): { declaredLen: number; hex: string } | null {
	if (!hasWirePrefix(data)) return null;

	const parts = data.trim().split(/\s+/);
	const hexStart = isWirePrefixToken(parts[0]) ? 2 : 1;
	const declaredLen = parseInt(parts[hexStart - 1], 10);
	if (!isUsableWireLength(declaredLen)) return null;

	return { declaredLen, hex: parts.slice(hexStart).join('') };
}

/** Decode exactly `declaredLen` bytes of hex; null if the hex length disagrees or a byte is not hex. */
function hexToBytes(hex: string, declaredLen: number): Uint8Array | null {
	if (hex.length !== declaredLen * 2) return null;

	const bytes = new Uint8Array(declaredLen);
	for (let i = 0; i < declaredLen; i++) {
		const b = parseInt(hex.substr(i * 2, 2), 16);
		if (!Number.isFinite(b)) return null;
		bytes[i] = b;
	}
	return bytes;
}

/** The raw rdata bytes of an RFC 3597 HTTPS record, or null if `data` is not (valid) wire format. */
function decodeWireRdata(data: string): Uint8Array | null {
	const tokens = splitWireTokens(data);
	if (!tokens) return null;
	return hexToBytes(tokens.hex, tokens.declaredLen);
}

/**
 * Walk the DNS labels of TargetName (which starts after the 2-byte priority) until the
 * terminating 0x00 label. Returns the offset of the first SvcParam, or null for a
 * compression pointer or a label overrunning the rdata.
 */
function skipTargetName(bytes: Uint8Array): number | null {
	let off = 2;
	while (off < bytes.length) {
		const labelLen = bytes[off++];
		if (labelLen === 0) break;
		if (labelLen >= 0xc0) return null; // compression pointers not permitted in SVCB
		off += labelLen;
		if (off > bytes.length) return null;
	}
	return off;
}

/** ALPN (SvcParam key 1): a sequence of length-prefixed protocol id strings (RFC 7301). */
function parseAlpnValue(value: Uint8Array): string[] {
	const alpn: string[] = [];
	const decoder = new TextDecoder();
	let p = 0;
	while (p < value.length) {
		const sLen = value[p++];
		if (p + sLen > value.length) break;
		alpn.push(decoder.decode(value.subarray(p, p + sLen)));
		p += sLen;
	}
	return alpn;
}

/** Walk the SvcParams from `off`, collecting ALPN (key 1) and noting ECH (key 5). A truncated param ends the walk. */
function parseSvcParams(bytes: Uint8Array, off: number): { alpn: string[]; ech: boolean } {
	const alpn: string[] = [];
	let ech = false;

	while (off + 4 <= bytes.length) {
		const key = (bytes[off] << 8) | bytes[off + 1];
		const len = (bytes[off + 2] << 8) | bytes[off + 3];
		off += 4;
		if (off + len > bytes.length) break;
		const value = bytes.subarray(off, off + len);
		off += len;

		if (key === 1) alpn.push(...parseAlpnValue(value));
		else if (key === 5) ech = true;
	}

	return { alpn, ech };
}

/**
 * Parse RFC 3597 wire-format HTTPS records: `\# <length> <hex bytes>`.
 * Cloudflare DoH JSON returns HTTPS (type 65) responses in this format rather
 * than the human-readable presentation form. Returns null if `data` is not in
 * wire format.
 */
function parseHttpsRecordWire(
	data: string,
): { priority: number; alpn: string[]; ech: boolean } | null {
	const bytes = decodeWireRdata(data);
	if (!bytes) return null;

	const paramsStart = skipTargetName(bytes);
	if (paramsStart === null) return null;

	const priority = (bytes[0] << 8) | bytes[1];
	const { alpn, ech } = parseSvcParams(bytes, paramsStart);
	return { priority, alpn, ech };
}

/** Capabilities accumulated across the answer's records; order-dependent (alias mode seen so far). */
interface HttpsCapabilities {
	hasH2: boolean;
	hasH3: boolean;
	hasEchParam: boolean;
	hasAliasMode: boolean;
}

/**
 * A THROWN lookup (transport error / timeout) never got a resolver's answer, so nothing
 * was measured: abstain in the not-assessed shape (checkStatus 'error', score 0, partial)
 * so scoring excludes the category. This used to return a COMPLETED `low` finding scored
 * 95 — a cut probe counted as measured evidence (SQ-201). An answered-empty or NXDOMAIN
 * lookup does not throw and still reaches the "No HTTPS record found" branch.
 * `recordPresent` stays undefined ("not determined"), never false.
 */
function queryFailedResult(domain: string): CheckResult {
	return buildNotAssessedResult(
		'svcb_https',
		createFinding(
			'svcb_https',
			'SVCB/HTTPS not assessed — HTTPS record query failed',
			'info',
			`DNS query for HTTPS records at ${domain} failed before any resolver answered. This is not evidence either way about SVCB/HTTPS publication — the category is excluded from scoring rather than passed. Re-run the check once name resolution is working.`,
			{ inconclusive: true, errorKind: 'dns_error' },
		),
		'error',
	);
}

function noHttpsRecordResult(domain: string): CheckResult {
	return buildCheckResult(
		'svcb_https',
		[
			createFinding(
				'svcb_https',
				'No HTTPS record found',
				'low',
				`No HTTPS (type 65) record found at ${domain}. HTTPS records (RFC 9460) advertise modern transport capabilities (ALPN, ECH) and enable clients to connect securely without an initial redirect round-trip. Consider publishing an HTTPS record with h2 and h3 ALPN support. Per RFC 9460 these records are an advisory performance/privacy optimization, not a required security control — absence is not a deficiency.`,
			),
		],
		undefined,
		false,
	);
}

function aliasModeFinding(domain: string, record: string): Finding {
	return createFinding(
		'svcb_https',
		'HTTPS record in alias mode',
		'info',
		`HTTPS record at ${domain} uses alias mode (priority 0): ${record}. This delegates SVCB parameters to a canonical name. Ensure the target also has valid HTTPS records.`,
		{ record, mode: 'alias' },
	);
}

function serviceRecordFinding(domain: string, record: string, priority: number | null, alpn: string[], ech: boolean): Finding {
	return createFinding(
		'svcb_https',
		'HTTPS record configured',
		'info',
		`HTTPS record found at ${domain} (priority ${priority}): ALPN=[${alpn.join(', ') || 'none'}]${ech ? ', ECH=present' : ''}.`,
		{ record, priority, alpn, ech },
	);
}

function missingAlpnFinding(domain: string, record: string): Finding {
	return createFinding(
		'svcb_https',
		'HTTPS record missing ALPN parameter',
		'low',
		`HTTPS record at ${domain} does not specify an ALPN parameter. Without ALPN, clients cannot use the record to negotiate HTTP/2 or HTTP/3 without an additional round-trip. Add alpn="h2" or alpn="h2,h3" to enable protocol negotiation.`,
		{ record },
	);
}

function noHttp2Finding(domain: string): Finding {
	return createFinding(
		'svcb_https',
		'HTTPS record does not advertise HTTP/2',
		'low',
		`HTTPS records at ${domain} do not include h2 in the ALPN list. HTTP/2 support via SVCB allows faster TLS negotiation. Add alpn="h2,h3" to enable HTTP/2 and HTTP/3 advertisement.`,
	);
}

function http3Finding(domain: string): Finding {
	return createFinding(
		'svcb_https',
		'HTTP/3 (QUIC) advertised via HTTPS record',
		'info',
		`HTTPS record at ${domain} advertises HTTP/3 (h3) ALPN, enabling QUIC-based transport. This provides improved performance and resilience, especially on lossy networks.`,
	);
}

function echFinding(domain: string): Finding {
	return createFinding(
		'svcb_https',
		'Encrypted Client Hello (ECH) advertised',
		'info',
		`HTTPS record at ${domain} includes ECH parameters. ECH encrypts the TLS SNI field, preventing passive observers from identifying the target hostname during connection establishment.`,
	);
}

/** ALPN and ECH of a service-mode record, from the wire form when it parsed, else the presentation form. */
function readServiceParams(record: string, wire: { alpn: string[]; ech: boolean } | null): { alpn: string[]; ech: boolean } {
	return { alpn: wire ? wire.alpn : parseAlpn(record), ech: wire ? wire.ech : hasEch(record) };
}

function noteCapabilities(state: HttpsCapabilities, alpn: string[], ech: boolean): void {
	if (alpn.includes('h2')) state.hasH2 = true;
	if (alpn.includes('h3')) state.hasH3 = true;
	if (ech) state.hasEchParam = true;
}

/** Service mode (priority >= 1, or an unparseable priority): the record finding, then the missing-ALPN flag. */
function analyzeServiceRecord(
	domain: string,
	record: string,
	wire: { alpn: string[]; ech: boolean } | null,
	priority: number | null,
	state: HttpsCapabilities,
): Finding[] {
	const { alpn, ech } = readServiceParams(record, wire);
	noteCapabilities(state, alpn, ech);

	const findings = [serviceRecordFinding(domain, record, priority, alpn, ech)];
	// Flag missing ALPN
	if (alpn.length === 0 && !state.hasAliasMode) findings.push(missingAlpnFinding(domain, record));
	return findings;
}

/** One record's findings; updates `state` in answer order (alias mode seen so far gates the missing-ALPN flag). */
function analyzeHttpsRecord(domain: string, record: string, state: HttpsCapabilities): Finding[] {
	const wire = parseHttpsRecordWire(record);
	const priority = wire ? wire.priority : parsePriority(record);

	if (priority === 0) {
		// Alias mode — delegates to another name for parameters
		state.hasAliasMode = true;
		return [aliasModeFinding(domain, record)];
	}

	return analyzeServiceRecord(domain, record, wire, priority, state);
}

/**
 * Summary findings for capabilities. Only reached for a non-empty answer, where every record
 * is either alias or service mode, so the former `validServiceModeRecords > 0 || hasAliasMode`
 * guard was always true and is not repeated here.
 */
function capabilitySummaryFindings(domain: string, state: HttpsCapabilities): Finding[] {
	const findings: Finding[] = [];
	if (!state.hasH2 && !state.hasAliasMode) findings.push(noHttp2Finding(domain));
	if (state.hasH3) findings.push(http3Finding(domain));
	if (state.hasEchParam) findings.push(echFinding(domain));
	return findings;
}

/** Analyze each HTTPS record in answer order, then the summary findings. */
function analyzeHttpsRecords(domain: string, httpsRecords: string[]): Finding[] {
	const findings: Finding[] = [];
	const state: HttpsCapabilities = { hasH2: false, hasH3: false, hasEchParam: false, hasAliasMode: false };

	for (const record of httpsRecords) findings.push(...analyzeHttpsRecord(domain, record, state));

	findings.push(...capabilitySummaryFindings(domain, state));
	return findings;
}

/**
 * Check HTTPS/SVCB records (RFC 9460) for a domain.
 * Validates the presence of HTTPS records and analyzes their contents
 * for modern transport capability advertisements.
 */
export async function checkSVCBHTTPS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;

	let httpsRecords: string[] = [];
	try {
		httpsRecords = await queryDNS(domain, 'HTTPS', { timeout });
	} catch {
		return queryFailedResult(domain);
	}

	if (httpsRecords.length === 0) return noHttpsRecordResult(domain);

	return buildCheckResult('svcb_https', analyzeHttpsRecords(domain, httpsRecords), undefined, true);
}
