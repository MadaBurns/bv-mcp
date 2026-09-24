// SPDX-License-Identifier: BUSL-1.1
//
// scripts/check-bindings.mjs's advisory bv-scanner-queue DLQ check (SQ-185).
// bv-scanner-queue had no dead_letter_queue: when the consumer exhausted
// max_retries on the 09-13 and 09-20 tenant cycles, 260/500 messages were
// dropped with no marker anywhere (SQ-169). This check warns — it must never
// fail the build, since the operator has to create the queue first.
//
// Imports the pure helpers directly (no subprocess, no `wrangler types`/`tsc`
// shell-out) — the module's `main()` only runs when invoked as the CLI
// entrypoint, guarded by `isInvokedDirectly` (mirrors
// scripts/ci/sidecar-deploy-drift-check.ts and its Node-pool audit test).

import { describe, expect, it, vi } from 'vitest';
import { assessScannerQueueDlq, extractConfigPath, warnIfScannerQueueMissingDlq } from '../../scripts/check-bindings.mjs';

describe('assessScannerQueueDlq', () => {
	it('warns when the bv-scanner-queue consumer has no dead_letter_queue', () => {
		const verdict = assessScannerQueueDlq({
			queues: { consumers: [{ queue: 'bv-scanner-queue', max_retries: 3 }] },
		});
		expect(verdict.ok).toBe(false);
		expect(verdict.message).toMatch(/bv-scanner-queue/);
		expect(verdict.message).toMatch(/dead_letter_queue/);
	});

	it('passes when the bv-scanner-queue consumer has a dead_letter_queue', () => {
		const verdict = assessScannerQueueDlq({
			queues: { consumers: [{ queue: 'bv-scanner-queue', dead_letter_queue: 'bv-scanner-dlq' }] },
		});
		expect(verdict.ok).toBe(true);
		expect(verdict.message).toBeNull();
	});

	it('passes (nothing to check) when there is no bv-scanner-queue consumer at all', () => {
		expect(assessScannerQueueDlq({ queues: { consumers: [{ queue: 'brand-audit-queue' }] } }).ok).toBe(true);
		expect(assessScannerQueueDlq({}).ok).toBe(true);
		expect(assessScannerQueueDlq(null).ok).toBe(true);
		expect(assessScannerQueueDlq(undefined).ok).toBe(true);
	});

	it('is unaffected by unrelated consumers sharing the queues block', () => {
		const verdict = assessScannerQueueDlq({
			queues: {
				consumers: [{ queue: 'brand-audit-queue', dead_letter_queue: 'brand-audit-dlq' }, { queue: 'bv-scanner-queue' }],
			},
		});
		expect(verdict.ok).toBe(false);
	});
});

describe('extractConfigPath', () => {
	it('reads the value following --config', () => {
		expect(extractConfigPath(['--config', 'wrangler.production.jsonc'])).toBe('wrangler.production.jsonc');
	});

	it('returns null when --config is absent (the default wrangler.jsonc has no queues to check)', () => {
		expect(extractConfigPath([])).toBeNull();
	});

	it('returns null when --config is the trailing arg with no value', () => {
		expect(extractConfigPath(['--config'])).toBeNull();
	});
});

describe('warnIfScannerQueueMissingDlq', () => {
	it('warns via console.warn when the consumer in the config file has no dead_letter_queue', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			const readFileFn = vi.fn(() => JSON.stringify({ queues: { consumers: [{ queue: 'bv-scanner-queue' }] } }));
			warnIfScannerQueueMissingDlq('wrangler.production.jsonc', readFileFn);
			expect(readFileFn).toHaveBeenCalledWith('wrangler.production.jsonc', 'utf8');
			expect(warnSpy).toHaveBeenCalledTimes(1);
			expect(warnSpy.mock.calls[0]?.[0]).toMatch(/bv-scanner-queue/);
		} finally {
			warnSpy.mockRestore();
		}
	});

	it('does not warn when the config path is null (no --config passed)', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			const readFileFn = vi.fn();
			warnIfScannerQueueMissingDlq(null, readFileFn);
			expect(readFileFn).not.toHaveBeenCalled();
			expect(warnSpy).not.toHaveBeenCalled();
		} finally {
			warnSpy.mockRestore();
		}
	});

	it('never throws on a missing or unparseable config file — this check is advisory only', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			const throwingReadFileFn = vi.fn(() => {
				throw new Error('ENOENT: no such file');
			});
			expect(() => warnIfScannerQueueMissingDlq('wrangler.production.jsonc', throwingReadFileFn)).not.toThrow();
			expect(warnSpy).not.toHaveBeenCalled();
		} finally {
			warnSpy.mockRestore();
		}
	});
});
