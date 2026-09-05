// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';

export const EVIDENCE_SCHEMA_VERSION = 'blackveil-evidence/v1' as const;
export const EVIDENCE_CANONICALIZATION = 'blackveil-cjson/v1' as const;

const EvidenceSourceSchema = z
	.object({
		serverName: z.string().min(1),
		serverVersion: z.string().min(1),
		endpointOrigin: z.string().url(),
		tool: z.string().min(1),
	})
	.strict();

export const EvidenceSnapshotSchema = z
	.object({
		schemaVersion: z.literal(EVIDENCE_SCHEMA_VERSION),
		capturedAt: z.string().datetime(),
		source: EvidenceSourceSchema,
		result: z.record(z.string(), z.unknown()),
		integrity: z
			.object({
				algorithm: z.literal('sha-256'),
				canonicalization: z.literal(EVIDENCE_CANONICALIZATION),
				digest: z.string().regex(/^[a-f0-9]{64}$/),
			})
			.strict(),
	})
	.strict();

export type EvidenceSnapshot = z.infer<typeof EvidenceSnapshotSchema>;

function canonicalize(value: unknown, seen: Set<object>): string {
	if (value === null) return 'null';
	if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
	if (typeof value === 'number') {
		if (!Number.isFinite(value)) throw new Error('Evidence contains a non-finite number');
		return JSON.stringify(value);
	}
	if (typeof value !== 'object') throw new Error(`Evidence contains an unsupported ${typeof value} value`);
	if (seen.has(value)) throw new Error('Evidence contains a circular reference');

	seen.add(value);
	try {
		if (Array.isArray(value)) {
			return `[${value.map((entry) => canonicalize(entry, seen)).join(',')}]`;
		}

		const record = value as Record<string, unknown>;
		const entries = Object.keys(record)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key], seen)}`);
		return `{${entries.join(',')}}`;
	} finally {
		seen.delete(value);
	}
}

/** Canonical JSON for the versioned BlackVeil evidence format. */
export function canonicalEvidenceJson(value: unknown): string {
	return canonicalize(value, new Set<object>());
}

/** Cryptographic integrity digest. This is not a signature or authenticity proof. */
export async function sha256Hex(value: string): Promise<string> {
	const bytes = new TextEncoder().encode(value);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

type UnsignedEvidenceSnapshot = Omit<EvidenceSnapshot, 'integrity'>;

async function digestUnsignedSnapshot(snapshot: UnsignedEvidenceSnapshot): Promise<string> {
	return sha256Hex(canonicalEvidenceJson(snapshot));
}

/** Seal a remote MCP result in a locally-verifiable evidence envelope. */
export async function createEvidenceSnapshot(args: {
	capturedAt: string;
	serverName: string;
	serverVersion: string;
	endpointOrigin: string;
	tool: string;
	result: Record<string, unknown>;
}): Promise<EvidenceSnapshot> {
	const unsigned: UnsignedEvidenceSnapshot = {
		schemaVersion: EVIDENCE_SCHEMA_VERSION,
		capturedAt: args.capturedAt,
		source: {
			serverName: args.serverName,
			serverVersion: args.serverVersion,
			endpointOrigin: args.endpointOrigin,
			tool: args.tool,
		},
		result: args.result,
	};
	const digest = await digestUnsignedSnapshot(unsigned);
	return {
		...unsigned,
		integrity: {
			algorithm: 'sha-256',
			canonicalization: EVIDENCE_CANONICALIZATION,
			digest,
		},
	};
}

export type EvidenceVerification =
	| { valid: true; snapshot: EvidenceSnapshot; expectedDigest: string; actualDigest: string }
	| { valid: false; snapshot: EvidenceSnapshot; expectedDigest: string; actualDigest: string };

/** Parse and verify an evidence envelope without trusting its embedded digest. */
export async function verifyEvidenceSnapshot(value: unknown): Promise<EvidenceVerification> {
	const snapshot = EvidenceSnapshotSchema.parse(value);
	const { integrity, ...unsigned } = snapshot;
	const actualDigest = await digestUnsignedSnapshot(unsigned);
	return {
		valid: actualDigest === integrity.digest,
		snapshot,
		expectedDigest: integrity.digest,
		actualDigest,
	};
}
