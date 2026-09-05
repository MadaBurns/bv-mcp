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
	if (records.length === 0) return { status: 'not-assessed', outcome: 'no_explicit_mx', targets: [], rejectedExchanges: [] };
	if (records.length === 1 && records[0]!.preference === 0 && records[0]!.exchange.trim() === '.') {
		return { status: 'not-applicable', outcome: 'null_mx', targets: [], rejectedExchanges: [] };
	}

	const targets: SmtpProbeTarget[] = [];
	const rejected = new Set<string>();
	const seenExchanges = new Set<string>();
	const ordered = [...records].sort(
		(a, b) => a.preference - b.preference || normalizedExchange(a.exchange).localeCompare(normalizedExchange(b.exchange)),
	);
	for (const record of ordered) {
		if (targets.length >= 3) break;
		const exchange = normalizedExchange(record.exchange);
		if (seenExchanges.has(exchange)) continue;
		seenExchanges.add(exchange);
		if (!Number.isInteger(record.preference) || record.preference < 0 || record.preference > 65_535 || !validateDomain(exchange).valid) {
			rejected.add(exchange || '<empty>');
			continue;
		}
		const address = [...new Set(record.addresses.filter(isPublicSmtpAddress))].sort()[0];
		if (!address) {
			rejected.add(exchange);
			continue;
		}
		targets.push({ exchange, preference: record.preference, address, port: 25, tlsServerName: exchange });
	}
	if (targets.length === 0) {
		return { status: 'not-assessed', outcome: 'no_public_mx_address', targets, rejectedExchanges: [...rejected].sort() };
	}
	return {
		status: rejected.size > 0 ? 'partial' : 'measured',
		outcome: 'targets_selected',
		targets,
		rejectedExchanges: [...rejected].sort(),
	};
}
