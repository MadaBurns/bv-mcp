// SPDX-License-Identifier: MIT

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

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

export function isNullMxRecord(record: ParsedMxRecord): boolean {
	return record.exchange === '' || record.exchange === '.';
}

export function getNullMxFinding(): Finding {
	return createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.');
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