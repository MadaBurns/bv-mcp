// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Pure RFC 9116 security.txt parsing and findings. No I/O: the fetch lives in check-security-txt.ts.
 */

import { createFinding } from '../check-utils';
import type { Finding, Severity } from '../types';

export interface ParsedSecurityTxt {
	contacts: string[];
	expires: string | null;
	/** `Expires` as a date; `null` when absent or not a parseable date-time. */
	expiresAt: Date | null;
	encryption: string[];
	policy: string[];
	canonical: string[];
	acknowledgments: string[];
	/** True when the file is an OpenPGP cleartext-signed message. */
	signed: boolean;
}

/** Where the file was found. */
export type SecurityTxtLocation = 'well-known' | 'legacy';

export interface SecurityTxtObservation {
	location: SecurityTxtLocation;
	/** The URL the body was served from (after any HTTPS redirect). */
	url: string;
	contentType: string | null;
	body: string;
}

const PGP_HEADER = '-----BEGIN PGP SIGNED MESSAGE-----';
const PGP_SIGNATURE = '-----BEGIN PGP SIGNATURE-----';
const FIELD_LINE = /^([A-Za-z][A-Za-z-]*):(.*)$/;
const URI_SCHEME = /^[a-z][a-z0-9+.-]*:\S/i;
const HTML_BODY = /<!doctype\s+html|<html[\s>]/i;

/** RFC 9116 section 2.5.5: Expires should be less than a year ahead. */
const MAX_AHEAD_MS = 366 * 24 * 60 * 60 * 1000;

/** The text inside an OpenPGP cleartext signature, or the input unchanged when it is not signed. */
function unsign(text: string): { content: string; signed: boolean } {
	const trimmed = text.trimStart();
	if (!trimmed.startsWith(PGP_HEADER)) return { content: text, signed: false };
	const lines = trimmed.split(/\r?\n/);
	const blank = lines.findIndex((line, i) => i > 0 && line.trim() === '');
	const body: string[] = [];
	for (const line of lines.slice(blank < 0 ? lines.length : blank + 1)) {
		if (line.startsWith(PGP_SIGNATURE)) break;
		body.push(line.startsWith('- ') ? line.slice(2) : line);
	}
	return { content: body.join('\n'), signed: true };
}

/** Parse security.txt text. Unknown fields and comments are ignored. */
export function parseSecurityTxt(text: string): ParsedSecurityTxt {
	const { content, signed } = unsign(text);
	const values: Record<string, string[]> = {};
	for (const raw of content.split(/\r?\n/)) {
		const line = raw.trim();
		if (line === '' || line.startsWith('#')) continue;
		const match = FIELD_LINE.exec(line);
		if (match) (values[match[1].toLowerCase()] ??= []).push(match[2].trim());
	}
	const expires = values.expires?.[0] ?? null;
	const parsed = expires === null ? Number.NaN : Date.parse(expires);
	return {
		contacts: values.contact ?? [],
		expires,
		expiresAt: Number.isNaN(parsed) ? null : new Date(parsed),
		encryption: values.encryption ?? [],
		policy: values.policy ?? [],
		canonical: values.canonical ?? [],
		acknowledgments: values.acknowledgments ?? [],
		signed,
	};
}

const find = (severity: Severity, title: string, detail: string, metadata?: Record<string, unknown>): Finding =>
	createFinding('security_txt', title, severity, detail, metadata);

/** The finding for a host that answers 404 on both paths. */
export function absentFinding(domain: string): Finding {
	return find(
		'low',
		'No security.txt found',
		`${domain} publishes no security.txt at /.well-known/security.txt or /security.txt. Publish one (RFC 9116) so researchers know where to report vulnerabilities.`,
		{ missingControl: true },
	);
}

/** True when a 200 response is a web page rather than a text file (a common false "present"). */
export function isHtmlResponse(contentType: string | null, body: string): boolean {
	return (contentType ?? '').toLowerCase().includes('text/html') || HTML_BODY.test(body.slice(0, 2048));
}

const sameUrl = (a: string, b: string): boolean => (URL.parse(a)?.href ?? a) === (URL.parse(b)?.href ?? b);

function expiryFindings(parsed: ParsedSecurityTxt, now: Date): Finding[] {
	if (parsed.expires === null) {
		return [find('medium', 'security.txt is missing Expires', 'RFC 9116 requires an Expires field so stale contact details can be recognised. Add "Expires:" with an ISO 8601 date-time.')];
	}
	if (parsed.expiresAt === null) {
		return [find('medium', 'security.txt Expires is not a valid date', `Expires "${parsed.expires}" is not an ISO 8601 date-time.`)];
	}
	if (parsed.expiresAt.getTime() < now.getTime()) {
		return [find('medium', 'security.txt has expired', `Expires ${parsed.expiresAt.toISOString()} is in the past, so the contact details can no longer be trusted. Renew the file.`)];
	}
	if (parsed.expiresAt.getTime() - now.getTime() > MAX_AHEAD_MS) {
		return [find('low', 'security.txt Expires is more than a year ahead', `Expires ${parsed.expiresAt.toISOString()} is over a year away; RFC 9116 section 2.5.5 recommends less than a year.`)];
	}
	return [];
}

function contactFindings(parsed: ParsedSecurityTxt): Finding[] {
	if (parsed.contacts.length === 0) {
		return [find('medium', 'security.txt is missing Contact', 'RFC 9116 requires at least one Contact field (a mailto:, https: or tel: URI).')];
	}
	const bad = parsed.contacts.filter((c) => !URI_SCHEME.test(c));
	return bad.length === 0
		? []
		: [find('low', 'security.txt Contact is not a URI', `Contact must be a URI such as mailto:security@example.com; found: ${bad.join(', ')}.`, { badContacts: bad })];
}

/** Findings for a security.txt that was served. */
export function analyzeSecurityTxt(observed: SecurityTxtObservation, now: Date): Finding[] {
	if (isHtmlResponse(observed.contentType, observed.body)) {
		return [
			find(
				'medium',
				'security.txt is served as an HTML page',
				`${observed.url} returned a web page (Content-Type ${observed.contentType ?? 'unknown'}), not a text/plain security.txt. This is usually a soft 404 or a catch-all route.`,
				{ url: observed.url, missingControl: true },
			),
		];
	}
	const parsed = parseSecurityTxt(observed.body);
	const findings: Finding[] = [...contactFindings(parsed), ...expiryFindings(parsed, now)];
	if (observed.location === 'legacy') {
		findings.push(find('low', 'security.txt found only at the legacy path', `${observed.url} works, but RFC 9116 requires /.well-known/security.txt. Serve it from the well-known path.`));
	}
	if (parsed.canonical.length > 0 && !parsed.canonical.some((c) => sameUrl(c, observed.url))) {
		findings.push(find('low', 'security.txt Canonical does not include its own URL', `${observed.url} is not listed in Canonical (${parsed.canonical.join(', ')}).`, { canonical: parsed.canonical }));
	}
	if (parsed.signed) findings.push(find('info', 'security.txt is PGP-signed', 'The file carries an OpenPGP cleartext signature.'));
	if (findings.every((f) => f.severity === 'info')) {
		findings.push(find('info', 'Valid security.txt found', `${observed.url} is a valid RFC 9116 security.txt.`));
	}
	const summary = {
		url: observed.url,
		location: observed.location,
		contactCount: parsed.contacts.length,
		policy: parsed.policy,
		encryption: parsed.encryption,
		canonical: parsed.canonical,
		expires: parsed.expires,
		signed: parsed.signed,
	};
	return findings.map((f, i) => (i === 0 ? { ...f, metadata: { ...f.metadata, ...summary } } : f));
}
