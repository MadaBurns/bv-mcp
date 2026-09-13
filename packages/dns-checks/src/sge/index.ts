// SPDX-License-Identifier: BUSL-1.1

/**
 * NZ Secure Government Email (SGE) — per-domain compliance evaluator.
 *
 * @module
 */

export { evaluateSgeCompliance } from './evaluate';
export { SGE_CONTROL_IDS } from './types';
export type {
	SgeControlId,
	SgeControlStatus,
	SgeNotMeasuredReason,
	SgeEvidence,
	SgeControlEvaluation,
	SgeVerdict,
	SgeMailTransport,
	SgeEvaluation,
	SgeSmtpTlsObservation,
	SgeEvaluateOptions,
} from './types';
