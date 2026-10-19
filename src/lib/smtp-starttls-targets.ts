// SPDX-License-Identifier: BUSL-1.1

import type { SmtpProbeTarget } from '../schemas/smtp-starttls';
import { validateDomain } from './sanitize';

export interface MxRecordWithAddresses {
	preference: number;
	exchange: string;
	addresses: string[];
}

export interface MxTargetSelection {
	status: 'measured' | 'partial' | 'not-assessed' | 'not-applicable';
	outcome: 'targets_selected' | 'null_mx' | 'no_explicit_mx' | 'no_public_mx_address';
	targets: SmtpProbeTarget[];
	rejectedExchanges: string[];
}

const MAX_SMTP_MX_TARGETS = 3;

function normalizedExchange(exchange: string): string {
	return exchange.trim().toLowerCase().replace(/\.$/u, '');
}

function publicIpv4(address: string): boolean {
	const parts = address.split('.');
	if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9]\d{0,2})$/u.test(part))) return false;
	const octets = parts.map(Number);
	if (octets.some((part) => part > 255)) return false;
	const [a, b] = octets;
	if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
	if (a === 100 && b >= 64 && b <= 127) return false;
	if (a === 169 && b === 254) return false;
	if (a === 172 && b >= 16 && b <= 31) return false;
	if (a === 192 && b === 0 && (octets[2] === 0 || octets[2] === 2)) return false;
	if (a === 192 && b === 31 && octets[2] === 196) return false;
	if (a === 192 && b === 52 && octets[2] === 193) return false;
	if (a === 192 && b === 88 && octets[2] === 99) return false;
	if (a === 192 && b === 168) return false;
	if (a === 192 && b === 175 && octets[2] === 48) return false;
	if (a === 198 && (b === 18 || b === 19)) return false;
	if (a === 198 && b === 51 && octets[2] === 100) return false;
	if (a === 203 && b === 0 && octets[2] === 113) return false;
	return true;
}

/**
 * Conservative public-address admission gate used before any future socket
 * connection. IPv6 is intentionally not admitted until the isolated probe has
 * a binary address classifier; textual prefix checks are not a security gate.
 */
export function isPublicSmtpAddress(address: string): boolean {
	return publicIpv4(address);
}

/**
 * Deterministically choose at most three MX hosts and pin one public address per
 * host. Lowest preference wins, then exchange and address lexical order.
 */
export function selectSmtpMxTargets(records: MxRecordWithAddresses[]): MxTargetSelection {
	const degenerate = degenerateSelection(records);
	if (degenerate) return degenerate;
	const { targets, rejected } = collectTargets(records);
	return buildSelection(targets, rejected);
}

/** The terminal selection for an empty record set or a null MX; undefined when real MX records need probing. */
function degenerateSelection(records: MxRecordWithAddresses[]): MxTargetSelection | undefined {
	if (records.length === 0) return { status: 'not-assessed', outcome: 'no_explicit_mx', targets: [], rejectedExchanges: [] };
	if (isNullMx(records)) return { status: 'not-applicable', outcome: 'null_mx', targets: [], rejectedExchanges: [] };
	return undefined;
}

/** Walk records in priority order, pinning up to MAX_SMTP_MX_TARGETS targets and noting rejected exchanges. */
function collectTargets(records: MxRecordWithAddresses[]): { targets: SmtpProbeTarget[]; rejected: Set<string> } {
	const targets: SmtpProbeTarget[] = [];
	const rejected = new Set<string>();
	const seenExchanges = new Set<string>();
	for (const record of orderMxRecords(records)) {
		if (targets.length >= MAX_SMTP_MX_TARGETS) break;
		const exchange = normalizedExchange(record.exchange);
		if (seenExchanges.has(exchange)) continue;
		seenExchanges.add(exchange);
		const result = toProbeTarget(record, exchange);
		if (typeof result === 'string') rejected.add(result);
		else targets.push(result);
	}
	return { targets, rejected };
}

/** A pinned probe target, or the label under which the exchange is reported as rejected. */
function toProbeTarget(record: MxRecordWithAddresses, exchange: string): SmtpProbeTarget | string {
	if (!isAdmissibleMxRecord(record, exchange)) return exchange || '<empty>';
	const address = firstPublicAddress(record.addresses);
	if (!address) return exchange;
	return { exchange, preference: record.preference, address, port: 25, tlsServerName: exchange };
}

/** RFC 7505 null MX: a single record with preference 0 and exchange ".". */
function isNullMx(records: MxRecordWithAddresses[]): boolean {
	return records.length === 1 && records[0]!.preference === 0 && records[0]!.exchange.trim() === '.';
}

/** Lowest preference first, then lexical normalized exchange. */
function orderMxRecords(records: MxRecordWithAddresses[]): MxRecordWithAddresses[] {
	return [...records].sort(
		(a, b) => a.preference - b.preference || normalizedExchange(a.exchange).localeCompare(normalizedExchange(b.exchange)),
	);
}

function isAdmissibleMxRecord(record: MxRecordWithAddresses, exchange: string): boolean {
	const validPreference = Number.isInteger(record.preference) && record.preference >= 0 && record.preference <= 65_535;
	return validPreference && validateDomain(exchange).valid;
}

/** The lexically first distinct public address, or undefined when none is public. */
function firstPublicAddress(addresses: string[]): string | undefined {
	return [...new Set(addresses.filter(isPublicSmtpAddress))].sort()[0];
}

function buildSelection(targets: SmtpProbeTarget[], rejected: Set<string>): MxTargetSelection {
	const rejectedExchanges = [...rejected].sort();
	if (targets.length === 0) return { status: 'not-assessed', outcome: 'no_public_mx_address', targets, rejectedExchanges };
	return { status: rejected.size > 0 ? 'partial' : 'measured', outcome: 'targets_selected', targets, rejectedExchanges };
}
