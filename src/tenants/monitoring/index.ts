// SPDX-License-Identifier: BUSL-1.1

/**
 * Continuous-monitoring primitives for Tenant (Phase-3 foundation).
 *
 * Wave-D will wire these into the weekly cron in `src/scheduled.ts`. For
 * now the module is foundation only — pure functions that the cron can
 * consume without pulling in MCP framing or Cloudflare-specific bindings.
 */

export { computeFingerprint, fingerprintsDiffer } from '../dns-fingerprint';
export type {
	ComputeFingerprintOptions,
	DnsFingerprintResult,
	DnsQueryFn,
	FingerprintRecords,
} from '../dns-fingerprint';
