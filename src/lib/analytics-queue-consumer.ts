// src/lib/analytics-queue-consumer.ts
// SPDX-License-Identifier: BUSL-1.1

import { getLogger, logError } from './log';
import { piiAllows } from './analytics-pii';
import { queryPtrRecords } from './dns';
import { accessLogInsertSql, accessLogBindings, encryptIpEvidence } from '../mcp/execute';
import type { AccessLogEvent } from './access-log-event';

/** Cap PTR subrequests per invocation well under the paid-plan 1000 ceiling. */
const MAX_PTR_LOOKUPS = 50;

export interface AnalyticsQueueEnv {
	INTELLIGENCE_DB?: D1Database;
	MCP_ACCESS_LOG_IP_ENCRYPTION_KEY?: string;
	MCP_ACCESS_LOG_IP_KEY_VERSION?: string;
}

/**
 * Drain a batch of AccessLogEvents: (PII-gated) reverse-DNS, encrypt the raw IP
 * at rest, then ONE D1 batch of per-row INSERTs. Fail-open, NO dead-letter:
 * a terminal failure acks (drops) the message so raw-IP payloads never linger.
 */
export async function handleAnalyticsQueue(batch: MessageBatch<unknown>, env: AnalyticsQueueEnv): Promise<void> {
	const db = env.INTELLIGENCE_DB;
	if (!db) {
		for (const m of batch.messages) m.ack();
		return;
	}
	const logger = getLogger();
	void logger; // logger reserved for future structured emission; kept fail-open
	const statements: D1PreparedStatement[] = [];
	let ptrBudget = MAX_PTR_LOOKUPS;

	for (const message of batch.messages) {
		try {
			const event = message.body as AccessLogEvent;
			const level = event.piiLevel ?? 'coarse';

			let ptrHostname: string | null = null;
			if (piiAllows(level, 'ptr') && ptrBudget > 0 && event.ip && event.ip !== 'unknown') {
				ptrBudget -= 1;
				const hosts = await queryPtrRecords(event.ip).catch(() => [] as string[]);
				ptrHostname = hosts[0] ?? null;
			}

			const ipCiphertext = piiAllows(level, 'ciphertext')
				? await encryptIpEvidence(event.ip, env.MCP_ACCESS_LOG_IP_ENCRYPTION_KEY)
				: null;
			const ipKeyVersion = ipCiphertext ? (env.MCP_ACCESS_LOG_IP_KEY_VERSION ?? 'v1') : null;

			statements.push(db.prepare(accessLogInsertSql()).bind(...accessLogBindings({ ...event, ptrHostname }, ipCiphertext, ipKeyVersion)));
		} catch (err) {
			// Per-message failure: drop fail-open (no DLQ — raw IP must not linger).
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'analytics',
				details: { stage: 'analytics_queue_message' },
			});
		}
	}

	if (statements.length > 0) {
		try {
			await db.batch(statements);
		} catch (err) {
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'analytics',
				details: { stage: 'analytics_queue_batch_insert', rows: statements.length },
			});
		}
	}
	for (const m of batch.messages) m.ack();
}
