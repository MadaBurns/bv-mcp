// SPDX-License-Identifier: BUSL-1.1

export type BrandAuditPipelineStep =
	| 'discovery'
	| 'registrar_enrichment'
	| 'classification'
	| 'csc_complement_fast'
	| 'csc_complement_full'
	| 'retry_scheduled';
export type BrandAuditStepPersistedStatus = 'completed' | 'partial' | 'failed';

export interface BrandAuditStepRecord {
	auditId: string;
	target: string;
	step: BrandAuditPipelineStep;
	status: BrandAuditStepPersistedStatus;
	payload: unknown;
	error?: string;
}

export interface BrandAuditStepStore {
	get(auditId: string, target: string, step: BrandAuditPipelineStep): Promise<BrandAuditStepRecord | null>;
	put(record: BrandAuditStepRecord): Promise<void>;
}

export class BrandAuditStepStoreError extends Error {
	readonly cause: unknown;

	constructor(operation: 'get' | 'put', cause: unknown) {
		const message = cause instanceof Error ? cause.message : String(cause);
		super(`brand_audit_step_store_${operation}_failed: ${message}`);
		this.name = 'BrandAuditStepStoreError';
		this.cause = cause;
	}
}

interface BrandAuditStepRow {
	audit_id: string;
	target: string;
	step: BrandAuditPipelineStep;
	status: BrandAuditStepPersistedStatus;
	payload_json: string | null;
	error: string | null;
}

function stepKey(auditId: string, target: string, step: BrandAuditPipelineStep): string {
	return `${auditId}\0${target}\0${step}`;
}

export function createMemoryBrandAuditStepStore(): BrandAuditStepStore {
	const records = new Map<string, BrandAuditStepRecord>();
	return {
		async get(auditId, target, step) {
			const record = records.get(stepKey(auditId, target, step));
			return record ? { ...record } : null;
		},
		async put(record) {
			records.set(stepKey(record.auditId, record.target, record.step), { ...record });
		},
	};
}

export function createD1BrandAuditStepStore(db: D1Database, now: () => number = Date.now): BrandAuditStepStore {
	return {
		async get(auditId, target, step) {
			let row: BrandAuditStepRow | null;
			try {
				row = (await db
					.prepare(
						'SELECT audit_id, target, step, status, payload_json, error FROM brand_audit_steps WHERE audit_id = ? AND target = ? AND step = ? LIMIT 1',
					)
					.bind(auditId, target, step)
					.first()) as BrandAuditStepRow | null;
			} catch (err) {
				throw new BrandAuditStepStoreError('get', err);
			}
			if (!row) return null;

			let payload: unknown = null;
			if (row.payload_json !== null) {
				try {
					payload = JSON.parse(row.payload_json);
				} catch {
					return {
						auditId: row.audit_id,
						target: row.target,
						step: row.step,
						status: 'failed',
						payload: null,
						error: row.error ?? 'Malformed payload_json in brand_audit_steps',
					};
				}
			}

			return {
				auditId: row.audit_id,
				target: row.target,
				step: row.step,
				status: row.status,
				payload,
				error: row.error ?? undefined,
			};
		},
		async put(record) {
			let payloadJson: string;
			try {
				payloadJson = JSON.stringify(record.payload) ?? 'null';
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				throw new Error(`brand_audit_step_payload_not_serializable: ${message}`);
			}
			try {
				await db
					.prepare(
						'INSERT INTO brand_audit_steps (audit_id, target, step, status, payload_json, error, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(audit_id, target, step) DO UPDATE SET status = excluded.status, payload_json = excluded.payload_json, error = excluded.error, updated_at = excluded.updated_at',
					)
					.bind(record.auditId, record.target, record.step, record.status, payloadJson, record.error ?? null, now())
					.run();
			} catch (err) {
				throw new BrandAuditStepStoreError('put', err);
			}
		},
	};
}
