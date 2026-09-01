// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import queueConfigText from '../../docs/provisioning/wrangler.async-batch-queues.json?raw';

describe('queue recovery configuration', () => {
	it('gives every production queue consumer bounded retries and a DLQ', () => {
		const config = JSON.parse(queueConfigText) as {
			queues?: { producers?: Array<{ binding: string; queue: string }>; consumers?: Array<Record<string, unknown>> };
		};
		const consumers = config.queues?.consumers ?? [];
		expect(consumers).toHaveLength(1);
		for (const consumer of consumers) {
			expect(consumer.max_retries).toBe(3);
			expect(consumer.dead_letter_queue).toMatch(/-dlq$/);
		}
		expect(config.queues?.producers).toContainEqual({ binding: 'ASYNC_BATCH_QUEUE', queue: 'async-batch-scan-queue' });
		expect(consumers).toContainEqual(
			expect.objectContaining({ queue: 'async-batch-scan-queue', max_batch_size: 1, dead_letter_queue: 'async-batch-scan-dlq' }),
		);
	});
});
