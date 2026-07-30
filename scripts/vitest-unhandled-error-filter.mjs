const WORKER_POOL_ERROR = '[vitest-pool]: Worker cloudflare-pool emitted error.';
const WORKER_EXIT_ERROR = 'Worker exited unexpectedly';

function errorMessage(value) {
	if (value instanceof Error) return value.message;
	if (value && typeof value === 'object' && 'message' in value && typeof value.message === 'string') return value.message;
	return '';
}

/**
 * Match only the Cloudflare pool's known process-exit wrapper. Application
 * errors, including other pool errors, must continue to fail the test run.
 *
 * @param {unknown} error
 */
export function isKnownWorkerdPoolShutdownError(error) {
	if (errorMessage(error) !== WORKER_POOL_ERROR || !error || typeof error !== 'object' || !('cause' in error)) return false;
	return errorMessage(error.cause) === WORKER_EXIT_ERROR;
}
