/** @vitest-environment node */
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const noisyWorkerPoolSpec = 'test/infra-probe-worker.spec.ts';

describe('vitest workerd stderr filter', () => {
	it('keeps expected Worker-pool teardown output free of peer-disconnect noise', () => {
		const result = spawnSync('npm', ['test', '--', noisyWorkerPoolSpec], {
			cwd: process.cwd(),
			encoding: 'utf8',
			env: {
				...process.env,
				FORCE_COLOR: '0',
				NO_COLOR: '1',
			},
		});

		const combinedOutput = `${result.stdout}\n${result.stderr}`;

		expect(result.status, combinedOutput).toBe(0);
		expect(combinedOutput).not.toContain('WebSocket peer disconnected');
		expect(combinedOutput).not.toContain('workerd/api/web-socket.c++');
	});
});
