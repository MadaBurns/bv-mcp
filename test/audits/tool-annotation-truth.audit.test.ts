// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: published tool metadata tells the truth.
//   (a) every published input property carries a description;
//   (b) openWorldHint is false for EXACTLY the declared closed-world set;
//   (c) readOnlyHint=true never co-occurs with destructiveHint=true;
//   (d) the two tools whose idempotency/read-only hints were corrected stay corrected.
//
// Per testing-methodology.md principle 4 — an audit replaces a review checklist.
// Without it a new tool can ship an undescribed parameter, or a closed-world
// reader can silently regress to the open-world default.

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../../src/schemas/tool-definitions';

/**
 * Tools that read ONLY our own D1/KV/DO state, bundled data, or the stored state
 * of a job already started — they never reach DNS/HTTP/third parties.
 * Adding or removing a name here is an intentional, reviewed edit.
 */
const CLOSED_WORLD_TOOLS = [
	'batch_scan_findings',
	'batch_scan_status',
	'brand_audit_get_report',
	'brand_audit_status',
	'delete_brand_audit_watch',
	'discover_brand_domains_findings',
	'discover_brand_domains_status',
	'explain_finding',
	'get_benchmark',
	'get_domain_rank',
	'get_provider_insights',
	'list_brand_audit_watches',
	'osint_investigation_status',
	'scan_buckets_findings',
	'scan_buckets_status',
].sort();

describe('tool annotations tell the truth', () => {
	it('every published input property has a non-empty description', () => {
		const missing: string[] = [];
		for (const tool of TOOLS) {
			const props = tool.inputSchema.properties as Record<string, { description?: unknown }>;
			for (const [prop, schema] of Object.entries(props)) {
				if (typeof schema?.description !== 'string' || schema.description.trim() === '') missing.push(`${tool.name}.${prop}`);
			}
		}
		expect(missing, `undescribed properties: ${missing.join(', ')}`).toEqual([]);
	});

	it('openWorldHint is false for exactly the declared closed-world set', () => {
		const closed = TOOLS.filter((t) => t.annotations?.openWorldHint === false)
			.map((t) => t.name)
			.sort();
		expect(closed).toEqual(CLOSED_WORLD_TOOLS);
		for (const tool of TOOLS) {
			expect(typeof tool.annotations?.openWorldHint, `${tool.name}.openWorldHint`).toBe('boolean');
		}
	});

	it('the open-world exceptions that compose network reads stay open-world', () => {
		for (const name of ['osint_investigation_report', 'generate', 'validate_fix', 'register_brand_audit_watch', 'check_spf']) {
			expect(TOOLS.find((t) => t.name === name)?.annotations?.openWorldHint, `${name} should stay open-world`).toBe(true);
		}
	});

	it('readOnlyHint=true never co-occurs with destructiveHint=true', () => {
		for (const tool of TOOLS) {
			expect(
				tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint === true,
				`${tool.name} is both read-only and destructive`,
			).toBe(false);
		}
	});

	it('batch_scan_start is idempotent (same args return the existing job) but still mutating', () => {
		const tool = TOOLS.find((t) => t.name === 'batch_scan_start')!;
		expect(tool.annotations?.idempotentHint).toBe(true);
		expect(tool.annotations?.readOnlyHint).toBe(false);
	});

	it('brand_audit_single is neither read-only nor idempotent (each uncached call charges a quota unit)', () => {
		const tool = TOOLS.find((t) => t.name === 'brand_audit_single')!;
		expect(tool.annotations?.readOnlyHint).toBe(false);
		expect(tool.annotations?.idempotentHint).toBe(false);
		expect(tool.annotations?.destructiveHint).toBe(false);
	});
});
