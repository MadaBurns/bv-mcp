// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: bv-intel-gateway `getDomainEvidence` RPC response shape.
 *
 * Pinned from the cross-Worker contract document § 1.2
 * (`docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md`).
 *
 * The producer (`bv-intel-gateway` Worker) and the consumer (this Worker, via
 * `tier2EvidenceLookup`) MUST agree on this shape. The schema is the source
 * of truth for the wire format — any field-name or type change requires a
 * coordinated change in both repos.
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service contract.
 */
import { describe, it, expect } from 'vitest';
import {
	DomainEvidenceResponseSchema,
	type DomainEvidenceResponse,
} from '../../src/schemas/cross-worker-domain-evidence';

// --- Producer view: what bv-intel-gateway emits ----------------------------

const producerOkResponse: DomainEvidenceResponse = {
	ok: true,
	domain: 'example.com',
	region: 'AMER',
	latestScan: { capturedAt: 1_779_000_000, score: 85, threatLevel: 'secure' },
	scanHistory: [{ capturedAt: 1_778_000_000, score: 84, threatLevel: 'secure' }],
	scoreAlerts: [
		{
			createdAt: 1_779_000_000,
			alertType: 'critical_drop',
			previousThreatLevel: 'low',
			newThreatLevel: 'critical',
			scoreDelta: -45,
		},
	],
};

const producerOkFalseResponse: DomainEvidenceResponse = {
	ok: false,
	error: 'not_in_corpus',
};

describe('DomainEvidenceResponseSchema contract (§ 1.2)', () => {
	// --- Producer (bv-intel-gateway) ----------------------------------------

	it('producer: accepts a well-formed ok=true response', () => {
		const parsed = DomainEvidenceResponseSchema.safeParse(producerOkResponse);
		expect(parsed.success).toBe(true);
	});

	it('producer: accepts ok=false with error reason (not_in_corpus / opted_out)', () => {
		const parsed = DomainEvidenceResponseSchema.safeParse(producerOkFalseResponse);
		expect(parsed.success).toBe(true);
	});

	it('producer: accepts region=null (seed not classified to any region)', () => {
		const parsed = DomainEvidenceResponseSchema.safeParse({ ...producerOkResponse, region: null });
		expect(parsed.success).toBe(true);
	});

	it('producer: accepts latestScan=null (in corpus, no scan history yet)', () => {
		const parsed = DomainEvidenceResponseSchema.safeParse({ ...producerOkResponse, latestScan: null });
		expect(parsed.success).toBe(true);
	});

	it('producer: accepts empty scanHistory and empty scoreAlerts', () => {
		const parsed = DomainEvidenceResponseSchema.safeParse({
			...producerOkResponse,
			scanHistory: [],
			scoreAlerts: [],
		});
		expect(parsed.success).toBe(true);
	});

	// --- Consumer (bv-mcp) — drift detection --------------------------------

	it('consumer: rejects unknown threatLevel enum value (producer would have drifted)', () => {
		const drifted = {
			...producerOkResponse,
			latestScan: { capturedAt: 1, score: 1, threatLevel: 'mostly-secure' },
		};
		const parsed = DomainEvidenceResponseSchema.safeParse(drifted);
		expect(parsed.success).toBe(false);
	});

	it('consumer: rejects unknown alertType enum value', () => {
		const drifted = {
			...producerOkResponse,
			scoreAlerts: [
				{
					createdAt: 1,
					alertType: 'mystery_event',
					previousThreatLevel: 'low',
					newThreatLevel: 'critical',
					scoreDelta: -10,
				},
			],
		};
		const parsed = DomainEvidenceResponseSchema.safeParse(drifted);
		expect(parsed.success).toBe(false);
	});

	it('consumer: rejects unknown region enum value', () => {
		const drifted = { ...producerOkResponse, region: 'ANTARCTICA' };
		const parsed = DomainEvidenceResponseSchema.safeParse(drifted);
		expect(parsed.success).toBe(false);
	});

	it('consumer: rejects missing `ok` discriminator', () => {
		const { ok, ...rest } = producerOkResponse;
		void ok;
		const parsed = DomainEvidenceResponseSchema.safeParse(rest);
		expect(parsed.success).toBe(false);
	});

	it('consumer: rejects ok=true response missing scanHistory (required array)', () => {
		const { scanHistory, ...rest } = producerOkResponse;
		void scanHistory;
		const parsed = DomainEvidenceResponseSchema.safeParse(rest);
		expect(parsed.success).toBe(false);
	});

	it('consumer: rejects ok=true response missing scoreAlerts (required array)', () => {
		const { scoreAlerts, ...rest } = producerOkResponse;
		void scoreAlerts;
		const parsed = DomainEvidenceResponseSchema.safeParse(rest);
		expect(parsed.success).toBe(false);
	});
});
