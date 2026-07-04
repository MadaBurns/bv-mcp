// SPDX-License-Identifier: BUSL-1.1

/**
 * Minimal Env stub for CI.
 *
 * Local development can augment this via generated worker-configuration.d.ts.
 */
interface Env {
	BV_INFRA_PROBE?: Fetcher;
}
