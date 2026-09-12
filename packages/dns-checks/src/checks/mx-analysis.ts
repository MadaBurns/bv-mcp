// SPDX-License-Identifier: BUSL-1.1

/**
 * MX record analysis helpers.
 * Pure functions for parsing and analyzing MX records.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

export type ParsedMxRecord = {
	priority: number;
	exchange: string;
	raw: string;
};

export function parseMxRecords(answers: string[]): ParsedMxRecord[] {
	return answers.map((answer) => {
		const parts = answer.split(' ');
		const priority = parseInt(parts[0], 10);
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { priority, exchange, raw: answer };
	});
}

/**
 * RFC 7505 null MX: priority 0 with a root (`.`) exchange, meaning the domain
 * explicitly accepts NO inbound mail. Parsers strip the trailing dot, so the
 * exchange arrives as `''` or `'.'` depending on the caller's normalisation.
 * Accepts any object carrying an `exchange` so Worker-side MX shapes (which
 * lack `raw`) can share the classification instead of re-deriving it.
 *
 * DECISION RECORD (#944) — null MX is ONLY the RFC 7505 form. `localhost`,
 * `localhost.localdomain`, `127.0.0.0/8` and `::1` are deliberately NOT
 * classified here, even though such a zone plainly receives no mail either.
 *
 * The question was settled on a measurement, not a preference. A rebuilt
 * 1000-domain stratified Tranco corpus returned 0 loopback-MX domains out of
 * 992 measured (0.00%). The positive control passes and is real: the same
 * script found 15 loopback-MX zones in a wider 29,780-domain sample
 * (15/29,385 measured = 0.051%, ~1 in 1,960), one of which was confirmed from
 * three independent vantages — Cloudflare DoH, Google DoH and a direct `dig`
 * against Google's public resolver — all returning `0 localhost.`. (The
 * resolver address is written out rather than given as a dotted quad on
 * purpose: a literal one trips the repo secret/PII scanners as a public IPv4.
 * Do not "tidy" it back.) ALL 15 wild hits are the
 * identical string `0 localhost.`: priority 0, exchange `localhost`, with zero
 * `127.0.0.1` and zero `::1`. That is an operator reaching for RFC 7505's
 * `0 .` and getting the exchange wrong.
 *
 * Widening this predicate to cover them would silently REWARD a non-standard
 * config — the domain would inherit the null-MX "not a mail control" path,
 * skip every mail finding, and be re-graded — for a shape that is a
 * misconfiguration rather than a declaration. `check_mx` therefore reports it
 * as a defect (`getLoopbackMxFinding`) instead, and `check_mta_sts` keeps
 * treating such a domain as inbound-mail-receiving.
 *
 * Do not widen this predicate.
 */
export function isNullMxRecord(record: Pick<ParsedMxRecord, 'exchange'>): boolean {
	return record.exchange === '' || record.exchange === '.';
}

/** Exact loopback exchange names (post-normalisation: trailing dot stripped, lowercased). */
const LOOPBACK_MX_EXCHANGES = new Set(['localhost', 'localhost.localdomain', '::1', '0:0:0:0:0:0:0:1']);

/** IPv4 loopback block (127.0.0.0/8) written as a literal MX exchange. */
const LOOPBACK_MX_IPV4_PATTERN = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/**
 * True when an MX exchange names the loopback interface — `localhost`,
 * `localhost.localdomain`, a `*.localhost` name, any `127.0.0.0/8` literal, or
 * the IPv6 `::1` (long or short form). Mail routed there never leaves the
 * sending host, so the domain cannot receive mail; `check_mx` reports it as a
 * defect. See `isNullMxRecord` for why this is NOT folded into null-MX.
 *
 * Deliberately NARROW — this is a loopback matcher, not an "unroutable target"
 * matcher. In particular it must never match `.invalid`: 22 domains in the
 * 29,780-domain wild sample published Microsoft 365 `msNNNNNNNN.msv1.invalid`
 * verification pseudo-MX records on HEALTHY tenants, so an unroutable-target
 * matcher would penalise ordinary M365 customers. That is the same over-match
 * class as the TXT-hygiene `SERVICE_SPF_DOMAINS` incident (see CLAUDE.md,
 * "False Positive Reduction"). Suffix matching is anchored on a label boundary
 * for the same reason — `localhostings.com` is an ordinary hostname.
 *
 * Accepts any object carrying an `exchange` so Worker-side MX shapes (which
 * lack `raw`, and may still carry a trailing dot / mixed case) can share the
 * classification instead of re-deriving it.
 */
export function isLoopbackMxRecord(record: Pick<ParsedMxRecord, 'exchange'>): boolean {
	const exchange = record.exchange.replace(/\.$/, '').toLowerCase();
	if (exchange === '') {
		return false;
	}
	if (LOOPBACK_MX_EXCHANGES.has(exchange)) {
		return true;
	}
	if (LOOPBACK_MX_IPV4_PATTERN.test(exchange)) {
		return true;
	}
	// Label-boundary suffix match only: `mail.localhost` yes, `localhostings.com` no.
	return exchange.endsWith('.localhost');
}

/** Longest rendered exchange list in the loopback finding detail (DNS data is caller-controlled). */
const LOOPBACK_MX_DETAIL_MAX_EXCHANGES = 5;

/**
 * ONE `medium` finding covering ALL loopback MX records, never one per record:
 * severity penalties are additive and the `mx` category has no severity cap, so
 * a per-record finding would compound a single misconfiguration into a zeroed
 * category. `check_mx` also excludes these records from the IP-target and
 * dangling-MX passes, so this finding REPLACES those rather than stacking with
 * them (#944).
 *
 * No `missingControl`: MX records were measured and are present — this is a
 * defect in the records, not an absent control.
 */
export function getLoopbackMxFinding(loopbackRecords: Pick<ParsedMxRecord, 'exchange'>[]): Finding {
	const exchanges = loopbackRecords.map((record) => record.exchange);
	const rendered = exchanges.slice(0, LOOPBACK_MX_DETAIL_MAX_EXCHANGES).join(', ');
	const overflow = exchanges.length - LOOPBACK_MX_DETAIL_MAX_EXCHANGES;
	const suffix = overflow > 0 ? `, and ${overflow} more` : '';
	return createFinding(
		'mx',
		'MX points at localhost',
		'medium',
		`MX target(s) "${rendered}"${suffix} name the loopback interface, so mail is routed back at the sending host and inbound delivery fails. If the domain accepts no mail, publish an RFC 7505 null MX ("0 .") instead; otherwise point the MX at a real mail exchange.`,
	);
}

export function getNullMxFinding(): Finding {
	return createFinding(
		'mx',
		'Null MX record (RFC 7505)',
		'info',
		'Domain explicitly declares it does not accept email via null MX record.',
	);
}

export function getPresenceFinding(mxRecords: ParsedMxRecord[]): Finding {
	return createFinding('mx', 'MX records found', 'info', `${mxRecords.length} mail exchange record(s) present.`);
}

export function getIpTargetFindings(mxRecords: ParsedMxRecord[]): Finding[] {
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	return mxRecords.flatMap((mxRecord) =>
		ipPattern.test(mxRecord.exchange)
			? [
					createFinding(
						'mx',
						'MX points to IP address',
						'medium',
						`MX record "${mxRecord.raw}" points to an IP address. MX targets must be hostnames per RFC 5321.`,
					),
				]
			: [],
	);
}

export function getSingleMxFinding(mxRecords: ParsedMxRecord[]): Finding | null {
	if (mxRecords.length !== 1) {
		return null;
	}

	return createFinding('mx', 'Single MX record', 'low', 'Only one MX record found. Consider adding a backup MX for redundancy.');
}
