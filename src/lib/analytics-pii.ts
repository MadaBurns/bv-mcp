// src/lib/analytics-pii.ts
// SPDX-License-Identifier: BUSL-1.1

/** Operator-chosen PII capture depth for the access log. */
export type AnalyticsPiiLevel = 'coarse' | 'standard' | 'full';

const LEVELS: readonly AnalyticsPiiLevel[] = ['coarse', 'standard', 'full'];

/** Parse `ANALYTICS_PII_LEVEL`; unknown/undefined → `coarse` (self-host-safe). */
export function parseAnalyticsPiiLevel(raw: string | undefined): AnalyticsPiiLevel {
	const v = (raw ?? '').trim().toLowerCase();
	return (LEVELS as readonly string[]).includes(v) ? (v as AnalyticsPiiLevel) : 'coarse';
}

type GatedField = 'ciphertext' | 'city' | 'precise_geo' | 'ptr';

/** Whether a PII level permits populating a given gated field. */
export function piiAllows(level: AnalyticsPiiLevel, field: GatedField): boolean {
	switch (field) {
		case 'ciphertext':
		case 'city':
			return level === 'standard' || level === 'full';
		case 'precise_geo':
		case 'ptr':
			return level === 'full';
	}
}
