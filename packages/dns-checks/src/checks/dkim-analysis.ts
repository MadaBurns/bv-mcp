// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM key analysis helpers.
 * Pure functions for analyzing DKIM key strength and consolidating findings.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

export type DkimKeyStrength = 'critical' | 'high' | 'medium' | 'info';

export type DkimKeyAnalysis = {
	bits: number | null;
	strength: DkimKeyStrength;
	keyType: 'rsa' | 'ed25519' | 'unknown';
};

export function getDkimTagValue(record: string, tag: string): string | undefined {
	if (!/^[a-zA-Z0-9]+$/.test(tag)) return undefined;
	const match = record.match(new RegExp(`(?:^|;)\\s*${tag}=([^;]*)`, 'i'));
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

	if (declaredKeyType === 'rsa-default' && charCount < 50) {
		return { bits: null, strength: 'medium', keyType: 'unknown' };
	}

	if (charCount < 150) {
		return { bits: 512, strength: 'critical', keyType: 'rsa' };
	}

	if (charCount < 230) {
		return { bits: 1024, strength: 'high', keyType: 'rsa' };
	}

	if (charCount < 380) {
		return { bits: 2048, strength: 'medium', keyType: 'rsa' };
	}

	// 2048-bit RSA keys produce ~392 base64 chars. Keys at or above this size
	// meet the current minimum recommendation — classify as info, not medium.
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
