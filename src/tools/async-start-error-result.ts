// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared rejected-request result for the asynchronous brand-audit / discovery tools
 * (`*_start`, `*_status`, `*_get_report`, `*_findings` and the watch tools).
 *
 * A refused or failed REQUEST (bad input, unknown id, quota, persistence/enqueue failure)
 * says nothing about the scanned domain. Producers still return a `CheckResult` (the
 * TOOL_REGISTRY return type), but they stamp the finding with {@link REJECTED_REQUEST_MARKER}
 * so the dispatch chokepoint in `handlers/tools.ts` can surface it as an MCP tool error
 * (`isError: true`, no `score`/`passed`, no impact boilerplate) instead of a scored HIGH
 * finding about the domain. The producer-level shape is unchanged, so direct callers and
 * their `{ [kind]: true }` metadata keep working.
 */
import { buildCheckResult, createFinding, type CheckCategory, type CheckResult } from '../lib/scoring';

/** Machine-readable kinds a rejected request can carry; `structuredContent.kind` is one of these. */
export const REJECTED_REQUEST_KINDS = [
	'invalidInput',
	'notFound',
	'quotaExceeded',
	'batchTooLarge',
	'watchLimitExceeded',
	'persistenceFailure',
	'enqueueFailure',
	'readFailure',
] as const;

export type RejectedRequestKind = (typeof REJECTED_REQUEST_KINDS)[number];

/** Finding-metadata key that routes a result to the tool-error path. Set only by {@link createRejectedRequestBuilder}. */
export const REJECTED_REQUEST_MARKER = 'requestRejected' as const;

/**
 * Leading words of the client-visible error. `sanitizeErrorMessage` (lib/json-rpc.ts) only
 * lets messages starting with an allowlisted prefix through. The three server-side failure
 * kinds have no allowlisted prefix that fits; they are returned as a result (never thrown),
 * so they are not sanitized and read `Error: <message>`.
 */
const KIND_PREFIX: Partial<Record<RejectedRequestKind, string>> = {
	invalidInput: 'Invalid request',
	batchTooLarge: 'Invalid request',
	notFound: 'Resource not found',
	quotaExceeded: 'Rate limit exceeded',
	watchLimitExceeded: 'Rate limit exceeded',
};

/**
 * Creates a typed rejected-request builder while preserving each producer's finding
 * category and human-readable title prefix.
 */
export function createRejectedRequestBuilder<Kind extends RejectedRequestKind | (string & {})>(
	category: CheckCategory,
	titlePrefix: string,
) {
	return (kind: Kind, message: string, extra: Record<string, unknown> = {}): CheckResult =>
		buildCheckResult(category, [
			createFinding(category, `${titlePrefix}: ${kind}`, 'high', message, {
				[kind]: true,
				...extra,
				[REJECTED_REQUEST_MARKER]: true,
				rejectionKind: kind,
			}),
		]);
}

/** A rejected request as the dispatch layer renders it. */
export interface RejectedRequest {
	kind: string;
	/** Allowlisted-prefix client text, without the leading `Error: `. */
	text: string;
	/** `structuredContent` for the tool error: the kind, the message and the producer's extras, never a verdict. */
	structured: Record<string, unknown>;
}

/** Returns the rejected request carried by `result`, or `undefined` for any ordinary result. */
export function getRejectedRequest(result: Pick<CheckResult, 'findings'>): RejectedRequest | undefined {
	const finding = (result.findings ?? []).find((f) => f.metadata?.[REJECTED_REQUEST_MARKER] === true);
	if (!finding) return undefined;
	const { [REJECTED_REQUEST_MARKER]: _marker, rejectionKind, ...rest } = finding.metadata ?? {};
	const kind = String(rejectionKind);
	// The producer sets `{ [kind]: true }` for direct callers; the tool error carries `kind` instead.
	delete rest[kind];
	const prefix = KIND_PREFIX[kind as RejectedRequestKind];
	return {
		kind,
		text: prefix ? `${prefix}: ${finding.detail}` : finding.detail,
		structured: { ...rest, kind, message: finding.detail },
	};
}
