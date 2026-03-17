// SPDX-License-Identifier: BUSL-1.1

import { queryDns } from './dns-transport';
import { RecordType, type QueryDnsOptions, type RecordTypeName } from './dns-types';

/** Parsed CAA record with flags, tag, and value */
export interface CaaRecord {
	flags: number;
	tag: string;
	value: string;
}

/** Parsed PTR record hostname */
export interface PtrRecord {
	hostname: string;
}

/** Parsed SRV record with priority, weight, port, and target */
export interface SrvRecord {
	priority: number;
	weight: number;
	port: number;
	target: string;
}

/** Parsed TLSA record with usage, selector, matching type, and certificate data */
export interface TlsaRecord {
	usage: number;
	selector: number;
	matchingType: number;
	certData: string;
}

/**
 * Query DNS and return just the answer data strings.
 * Returns an empty array if no answers are found.
 */
export async function queryDnsRecords(domain: string, type: RecordTypeName, opts?: QueryDnsOptions): Promise<string[]> {
	const resp = await queryDns(domain, type, false, opts);
	return (resp.Answer ?? []).filter((answer) => answer.type === RecordType[type]).map((answer) => answer.data);
}

/**
 * Query TXT records and strip surrounding quotes from values.
 * Cloudflare DoH returns TXT data with surrounding quotes.
 */
export async function queryTxtRecords(domain: string, opts?: QueryDnsOptions): Promise<string[]> {
	const records = await queryDnsRecords(domain, 'TXT', opts);
	return records.map((record) =>
		record
			.replace(/" "/g, ' ')
			.replace(/^"|"$/g, ''),
	);
}

/**
 * Check if a domain has valid DNSSEC by examining the AD (Authenticated Data) flag.
 * Returns true if the response was DNSSEC-validated.
 */
export async function checkDnssec(domain: string, opts?: QueryDnsOptions): Promise<boolean> {
	const resp = await queryDns(domain, 'A', true, opts);
	return resp.AD === true;
}

/**
 * Parse a single CAA record data string.
 * Handles both human-readable format (e.g. `0 issue "letsencrypt.org"`)
 * and Cloudflare DoH hex wire format (e.g. `\# 19 00 05 69 73 73 75 65...`).
 *
 * Wire format bytes: flags(1) + tag_length(1) + tag(tag_length) + value(rest)
 */
export function parseCaaRecord(data: string): CaaRecord | null {
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 3) return null;

		const flags = parseInt(hexBytes[0], 16);
		const tagLen = parseInt(hexBytes[1], 16);
		if (isNaN(flags) || isNaN(tagLen) || hexBytes.length < 2 + tagLen) return null;

		const tag = hexBytes
			.slice(2, 2 + tagLen)
			.map((hexByte) => String.fromCharCode(parseInt(hexByte, 16)))
			.join('');
		const value = hexBytes
			.slice(2 + tagLen)
			.map((hexByte) => String.fromCharCode(parseInt(hexByte, 16)))
			.join('');

		return { flags, tag: tag.toLowerCase(), value };
	}

	const match = data.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$/);
	if (match) {
		return {
			flags: parseInt(match[1], 10),
			tag: match[2].toLowerCase(),
			value: match[3],
		};
	}

	return null;
}

/**
 * Query CAA records and parse them into structured objects.
 * Handles both human-readable and hex wire format from DoH.
 */
export async function queryCaaRecords(domain: string, opts?: QueryDnsOptions): Promise<CaaRecord[]> {
	const records = await queryDnsRecords(domain, 'CAA', opts);
	return records.map(parseCaaRecord).filter((record): record is CaaRecord => record !== null);
}

/**
 * Query MX records and parse them into priority + exchange pairs.
 */
export async function queryMxRecords(domain: string, opts?: QueryDnsOptions): Promise<Array<{ priority: number; exchange: string }>> {
	const records = await queryDnsRecords(domain, 'MX', opts);
	return records.map((record) => {
		const parts = record.split(' ');
		return {
			priority: parseInt(parts[0], 10),
			exchange: parts.slice(1).join(' ').replace(/\.$/, ''),
		};
	});
}

/**
 * Query PTR records for an IP address by constructing the reverse DNS name.
 * For IPv4 address `192.0.2.1`, queries `1.2.0.192.in-addr.arpa`.
 * Returns an array of PTR hostnames with trailing dots stripped.
 */
export async function queryPtrRecords(ip: string, opts?: QueryDnsOptions): Promise<string[]> {
	const reverseName = ip.split('.').reverse().join('.') + '.in-addr.arpa';
	const records = await queryDnsRecords(reverseName, 'PTR', opts);
	return records.map((record) => record.replace(/\.$/, ''));
}

/**
 * Query SRV records and parse them into structured objects.
 * SRV data format: `priority weight port target`
 */
export async function querySrvRecords(
	name: string,
	opts?: QueryDnsOptions,
): Promise<Array<{ priority: number; weight: number; port: number; target: string }>> {
	const records = await queryDnsRecords(name, 'SRV', opts);
	return records.map((record) => {
		const parts = record.split(' ');
		return {
			priority: parseInt(parts[0], 10),
			weight: parseInt(parts[1], 10),
			port: parseInt(parts[2], 10),
			target: parts.slice(3).join(' ').replace(/\.$/, ''),
		};
	});
}

/**
 * Parse a TLSA record data string into structured fields.
 * Handles both human-readable format (`usage selector matchingType certData`)
 * and hex wire format (data starting with `\#`).
 *
 * Returns null if the data cannot be parsed.
 */
export function parseTlsaRecord(data: string): TlsaRecord | null {
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 4) return null;

		const usage = parseInt(hexBytes[0], 16);
		const selector = parseInt(hexBytes[1], 16);
		const matchingType = parseInt(hexBytes[2], 16);
		if (isNaN(usage) || isNaN(selector) || isNaN(matchingType)) return null;

		const certData = hexBytes.slice(3).join('');
		return { usage, selector, matchingType, certData };
	}

	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;

	const usage = parseInt(parts[0], 10);
	const selector = parseInt(parts[1], 10);
	const matchingType = parseInt(parts[2], 10);
	if (isNaN(usage) || isNaN(selector) || isNaN(matchingType)) return null;

	const certData = parts.slice(3).join('');
	return { usage, selector, matchingType, certData };
}