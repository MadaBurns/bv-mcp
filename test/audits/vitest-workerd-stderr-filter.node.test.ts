/** @vitest-environment node */
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { isKnownWorkerdPoolShutdownError } from '../../scripts/vitest-unhandled-error-filter.mjs';
import { createFilteredWriter } from '../../scripts/vitest-workerd-stderr-filter.mjs';

/** In-memory sink so writer output can be asserted on without touching real stdio. */
function collectingSink() {
	let output = '';
	return {
		write(text: string) {
			output += text;
		},
		get output() {
			return output;
		},
	};
}

const NOISE_LINE = 'exception = workerd/api/web-socket.c++:123: disconnected: WebSocket peer disconnected';

describe('vitest workerd stderr filter', () => {
	it('filters only the known Cloudflare pool shutdown wrapper', () => {
		const knownShutdownError = Object.assign(new Error('[vitest-pool]: Worker cloudflare-pool emitted error.'), {
			cause: new Error('Worker exited unexpectedly'),
			type: 'Unhandled Error',
		});

		expect(isKnownWorkerdPoolShutdownError(knownShutdownError)).toBe(true);
		expect(isKnownWorkerdPoolShutdownError(new TypeError('Response body stream is locked'))).toBe(false);
		expect(
			isKnownWorkerdPoolShutdownError(
				Object.assign(new Error('[vitest-pool]: Worker cloudflare-pool emitted error.'), {
					cause: new Error('Application rejection'),
				}),
			),
		).toBe(false);
	});

	it('drops the exact workerd peer-disconnect line', () => {
		const sink = collectingSink();
		const writer = createFilteredWriter(sink);

		writer.write(`${NOISE_LINE}\n`);
		writer.flush();

		expect(sink.output).not.toContain(NOISE_LINE);
	});

	it('passes through a near-miss with a different message', () => {
		const sink = collectingSink();
		const writer = createFilteredWriter(sink);
		const nearMiss = 'exception = workerd/api/web-socket.c++:123: disconnected: something else entirely';

		writer.write(`${nearMiss}\n`);
		writer.flush();

		expect(sink.output).toContain(nearMiss);
	});

	it('passes through the pattern text embedded mid-line rather than as a whole line', () => {
		const sink = collectingSink();
		const writer = createFilteredWriter(sink);
		const embedded = `prefix: ${NOISE_LINE} suffix`;

		writer.write(`${embedded}\n`);
		writer.flush();

		expect(sink.output).toContain(embedded);
	});

	it('keeps a line intact when it is split across chunk boundaries, dropping it once reassembled', () => {
		const sink = collectingSink();
		const writer = createFilteredWriter(sink);
		const splitPoint = NOISE_LINE.indexOf('disconnected: WebSocket');

		writer.write(NOISE_LINE.slice(0, splitPoint));
		writer.write(`${NOISE_LINE.slice(splitPoint)}\n`);
		writer.flush();

		expect(sink.output).not.toContain('WebSocket peer disconnected');
		expect(sink.output).not.toContain('workerd/api/web-socket.c++');
	});

	it('keeps a non-matching line intact when split across chunks, emitting only on flush without a trailing newline', () => {
		const sink = collectingSink();
		const writer = createFilteredWriter(sink);

		writer.write('hello inter');
		writer.write('esting world');
		// No trailing newline yet: the partial line must not be emitted until flush().
		expect(sink.output).toBe('');

		writer.flush();

		expect(sink.output).toBe('hello interesting world\n');
	});

	it('keeps expected teardown output free of peer-disconnect noise (positive + negative control)', () => {
		const sentinel = 'AUDIT-AUDIT-SENTINEL-SURVIVES';
		// A synthetic child, not the real workerd pool, so this test does not depend on the
		// Workers pool actually emitting the noise line (it doesn't reliably — see SQ-158).
		const inlineScript = [
			`process.stderr.write(${JSON.stringify(`${NOISE_LINE}\n`)});`,
			`process.stderr.write(${JSON.stringify(`${sentinel}\n`)});`,
		].join('\n');

		const result = spawnSync(process.execPath, ['-e', inlineScript], { encoding: 'utf8' });
		expect(result.status, result.stderr).toBe(0);

		const sink = collectingSink();
		const writer = createFilteredWriter(sink);
		writer.write(result.stderr);
		writer.flush();

		expect(sink.output).toContain(sentinel);
		expect(sink.output).not.toContain('WebSocket peer disconnected');
		expect(sink.output).not.toContain('workerd/api/web-socket.c++');
	});
});
