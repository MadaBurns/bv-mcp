// SPDX-License-Identifier: BUSL-1.1

/**
 * TLS-RPT (`_smtp._tls`) record parsing — RFC 8460 §3.1.
 *
 * The reporting destinations are published as a comma-separated URI list inside a single
 * `rua=` tag, and the tag itself is one `;`-delimited element of the record. Two scored
 * checks read that tag: `check-tlsrpt.ts` (category `tlsrpt`) and `mta-sts-analysis.ts`
 * (category `mta_sts`). Each used to carry its own regex, and because the regexes differed
 * they reached OPPOSITE conclusions about the same record — a domain could be penalised in
 * one category and credited in the other for identical DNS data. One parser, one verdict.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

/** Reading of the `rua=` tag out of a TLS-RPT record. */
export interface TlsRptRua {
	/** A `rua=` tag was present as its own tagged element. */
	present: boolean;
	/** The URI list, whitespace-trimmed, with empty elements removed. */
	uris: string[];
	/** Members of {@link uris} that are not an acceptable `mailto:` or `https:` destination. */
	invalid: string[];
}

/**
 * A `mailto:` destination needs an address. The trailing `.` requirement is kept from the
 * pre-parser rules so that a dotless host (`mailto:postmaster@localhost`) still reads as
 * the unusable destination it was before this module existed.
 */
const MAILTO_URI = /^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** An `https:` collection endpoint. Path/query shape is the collector's problem, not ours. */
const HTTPS_URI = /^https:\/\/.+/;

/**
 * Parse the `rua=` tag out of a TLS-RPT record.
 *
 * Deliberate differences from the two regexes this replaces:
 *
 * - The tag is matched as a whole `;`-delimited element, so `xrua=…` is no longer read as a
 *   reporting destination. The `mta_sts` scan previously matched it anywhere, which both
 *   invented a `rua` verdict for an unrelated tag and masked a genuinely missing one.
 * - The value runs to the next `;`, not to the next space. Truncating at whitespace made
 *   every URI after the first space invisible to validation, so
 *   `rua=mailto:a@example.com,junk-not-a-uri` scored clean while `rua=` lists containing a
 *   legal space after the comma produced a phantom empty element and a false violation.
 */
export function parseTlsRptRua(record: string): TlsRptRua {
	let value: string | undefined;
	for (const part of record.split(';')) {
		const trimmed = part.trim();
		const eq = trimmed.indexOf('=');
		if (eq <= 0) continue;
		if (trimmed.slice(0, eq).trim().toLowerCase() !== 'rua') continue;
		value = trimmed.slice(eq + 1).trim();
		// A duplicated `rua=` tag is itself a malformed record; take the first and let the
		// multi-record hygiene check account for the rest.
		break;
	}

	if (value === undefined) {
		return { present: false, uris: [], invalid: [] };
	}

	// RFC 8460 borrows DMARC's tagged-questions syntax, which allows a quoted value.
	if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
		value = value.slice(1, -1);
	}

	const uris = value
		.split(',')
		.map((uri) => uri.trim())
		.filter((uri) => uri.length > 0);
	const invalid = uris.filter((uri) => !MAILTO_URI.test(uri) && !HTTPS_URI.test(uri));

	return { present: true, uris, invalid };
}
