// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import { isPublicSmtpAddress } from '../lib/smtp-starttls-targets';
import { validateDomain } from '../lib/sanitize';

/** A single public-IP target selected from an MX RRset. Port is fixed by contract. */
export const SmtpProbeTargetSchema = z
	.object({
		exchange: z.string().min(1).max(253),
		preference: z.number().int().min(0).max(65_535),
		address: z.ipv4().refine(isPublicSmtpAddress, 'SMTP target must be a canonical public IPv4 address'),
		port: z.literal(25),
		tlsServerName: z.string().min(1).max(253),
	})
	.strict()
	.superRefine((target, ctx) => {
		if (!validateDomain(target.exchange).valid || target.exchange !== target.exchange.toLowerCase() || target.exchange.endsWith('.')) {
			ctx.addIssue({ code: 'custom', message: 'SMTP exchange must be a normalized public DNS hostname' });
		}
		if (target.tlsServerName !== target.exchange) {
			ctx.addIssue({ code: 'custom', message: 'TLS server name must equal the selected MX exchange' });
		}
	});

export type SmtpProbeTarget = z.infer<typeof SmtpProbeTargetSchema>;

const SmtpPhaseSchema = z.enum(['connect', 'banner', 'ehlo', 'starttls', 'tls', 'post_tls_ehlo', 'quit']);
const SmtpTargetFailureReasonSchema = z.enum([
	'connection_failed',
	'deadline_exceeded',
	'invalid_reply',
	'reply_limit_exceeded',
	'starttls_not_advertised',
	'starttls_rejected',
	'tls_handshake_failed',
	'peer_name_invalid',
	'post_tls_ehlo_failed',
]);
const SmtpNotAssessedReasonSchema = z.enum([
	'probe_unprovisioned',
	'invalid_domain',
	'no_explicit_mx',
	'no_public_mx_address',
	'probe_failed',
	'probe_response_invalid',
]);
export type SmtpNotAssessedReason = z.infer<typeof SmtpNotAssessedReasonSchema>;
const SmtpTlsSchema = z
	.object({
		protocol: z.string().min(1).max(32),
		cipher: z.string().min(1).max(128).optional(),
		peerNameValid: z.boolean(),
	})
	.strict();

export const SmtpMeasuredTargetResultSchema = z
	.object({
		target: SmtpProbeTargetSchema,
		status: z.literal('measured'),
		phase: SmtpPhaseSchema,
		starttlsAdvertised: z.boolean(),
		tlsNegotiated: z.boolean(),
		postTlsEhloAccepted: z.boolean(),
		tls: SmtpTlsSchema.optional(),
		reason: SmtpTargetFailureReasonSchema.optional(),
	})
	.strict();

const SmtpPartialTargetResultSchema = z
	.object({
		target: SmtpProbeTargetSchema,
		status: z.literal('partial'),
		phase: SmtpPhaseSchema,
		starttlsAdvertised: z.boolean().nullable(),
		tlsNegotiated: z.boolean().nullable(),
		postTlsEhloAccepted: z.boolean().nullable(),
		tls: SmtpTlsSchema.optional(),
		reason: SmtpTargetFailureReasonSchema,
	})
	.strict();

const SmtpNotAssessedTargetResultSchema = z
	.object({
		target: SmtpProbeTargetSchema,
		status: z.literal('not-assessed'),
		phase: SmtpPhaseSchema,
		reason: SmtpTargetFailureReasonSchema,
	})
	.strict();

export const SmtpTargetResultSchema = z
	.discriminatedUnion('status', [SmtpMeasuredTargetResultSchema, SmtpPartialTargetResultSchema, SmtpNotAssessedTargetResultSchema])
	.superRefine((result, ctx) => {
		if (result.status === 'not-assessed') return;
		if (result.tlsNegotiated === true && result.starttlsAdvertised !== true) {
			ctx.addIssue({ code: 'custom', message: 'TLS negotiation requires an advertised STARTTLS capability' });
		}
		if ((result.tlsNegotiated === true) !== (result.tls !== undefined)) {
			ctx.addIssue({ code: 'custom', message: 'TLS details must be present exactly when TLS was negotiated' });
		}
		if (result.postTlsEhloAccepted === true && result.tlsNegotiated !== true) {
			ctx.addIssue({ code: 'custom', message: 'A post-TLS greeting requires a negotiated TLS session' });
		}
		if (result.status === 'measured') {
			const successful = result.tlsNegotiated && result.postTlsEhloAccepted && result.tls?.peerNameValid === true;
			if (successful === (result.reason !== undefined)) {
				ctx.addIssue({ code: 'custom', message: 'A measured failed target requires one reason; a successful target permits none' });
			}
		}
	});

export type SmtpTargetResult = z.infer<typeof SmtpTargetResultSchema>;

function targetKnownAvailable(target: SmtpTargetResult): boolean {
	return (
		target.status !== 'not-assessed' &&
		target.starttlsAdvertised === true &&
		target.tlsNegotiated === true &&
		target.postTlsEhloAccepted === true &&
		target.tls?.peerNameValid === true
	);
}

function targetKnownUnavailable(target: SmtpTargetResult): boolean {
	return (
		target.status !== 'not-assessed' &&
		(target.starttlsAdvertised === false ||
			target.tlsNegotiated === false ||
			target.postTlsEhloAccepted === false ||
			target.tls?.peerNameValid === false)
	);
}

const SmtpResultBase = {
	schemaVersion: z.literal('1.0'),
	probe: z.literal('smtp_starttls'),
	observedAt: z.string().datetime(),
	nonScoring: z.literal(true),
};

const SmtpMeasuredResultSchema = z
	.object({
		...SmtpResultBase,
		domain: z.string().min(1).max(253),
		status: z.literal('measured'),
		outcome: z.enum(['starttls_available', 'starttls_unavailable']),
		targets: z.array(SmtpTargetResultSchema).min(1).max(3),
	})
	.strict();

const SmtpPartialResultSchema = z
	.object({
		...SmtpResultBase,
		domain: z.string().min(1).max(253),
		status: z.literal('partial'),
		outcome: z.enum(['starttls_available', 'starttls_unavailable', 'mixed']),
		targets: z.array(SmtpTargetResultSchema).min(1).max(3),
	})
	.strict();

const SmtpNotAssessedResultSchema = z
	.object({
		...SmtpResultBase,
		domain: z.string().min(1).max(253).nullable(),
		status: z.literal('not-assessed'),
		outcome: z.enum(['no_explicit_mx', 'not_assessed']),
		targets: z.array(SmtpTargetResultSchema).length(0),
		reason: SmtpNotAssessedReasonSchema,
	})
	.strict();

const SmtpNotApplicableResultSchema = z
	.object({
		...SmtpResultBase,
		domain: z.string().min(1).max(253),
		status: z.literal('not-applicable'),
		outcome: z.literal('null_mx'),
		targets: z.array(SmtpTargetResultSchema).length(0),
		reason: z.literal('null_mx'),
	})
	.strict();

export const SmtpStarttlsResultSchema = z
	.discriminatedUnion('status', [
		SmtpMeasuredResultSchema,
		SmtpPartialResultSchema,
		SmtpNotAssessedResultSchema,
		SmtpNotApplicableResultSchema,
	])
	.superRefine((result, ctx) => {
		if (result.status === 'measured') {
			const measuredTargets = result.targets.filter((target) => target.status === 'measured');
			if (measuredTargets.length !== result.targets.length) {
				ctx.addIssue({ code: 'custom', message: 'A measured aggregate cannot contain partial or not-assessed targets' });
				return;
			}
			const successful = measuredTargets.filter(
				(target) => target.tlsNegotiated && target.postTlsEhloAccepted && target.tls?.peerNameValid === true,
			).length;
			if (result.outcome === 'starttls_available' && successful !== result.targets.length) {
				ctx.addIssue({ code: 'custom', message: 'An available measured result requires every target to complete STARTTLS' });
			}
			if (result.outcome === 'starttls_unavailable' && successful !== 0) {
				ctx.addIssue({ code: 'custom', message: 'An unavailable measured result cannot include a successful STARTTLS target' });
			}
		}
		if (result.status === 'partial') {
			const hasIncompleteEvidence = result.targets.some((target) => target.status !== 'measured');
			const hasKnownAvailable = result.targets.some(targetKnownAvailable);
			const hasKnownUnavailable = result.targets.some(targetKnownUnavailable);

			if (result.outcome === 'mixed') {
				if (!hasIncompleteEvidence && !(hasKnownAvailable && hasKnownUnavailable)) {
					ctx.addIssue({
						code: 'custom',
						message: 'A mixed partial result requires both measured outcomes or an explicit partial/not-assessed target',
					});
				}
			} else {
				if (hasIncompleteEvidence) {
					ctx.addIssue({ code: 'custom', message: 'A uniform STARTTLS outcome cannot contain incomplete target evidence' });
				}
				const contradictsAvailable = result.outcome === 'starttls_available' && hasKnownUnavailable;
				const contradictsUnavailable = result.outcome === 'starttls_unavailable' && hasKnownAvailable;
				if (contradictsAvailable || contradictsUnavailable) {
					ctx.addIssue({ code: 'custom', message: 'Known target evidence contradicts the aggregate STARTTLS outcome' });
				}
				if (!hasIncompleteEvidence && !contradictsAvailable && !contradictsUnavailable) {
					ctx.addIssue({ code: 'custom', message: 'Uniform complete target evidence must use measured aggregate status' });
				}
			}
		}
		if (result.status === 'not-assessed') {
			if ((result.outcome === 'no_explicit_mx') !== (result.reason === 'no_explicit_mx')) {
				ctx.addIssue({ code: 'custom', message: 'The no-explicit-MX outcome and reason must agree' });
			}
			if ((result.reason === 'invalid_domain') !== (result.domain === null)) {
				ctx.addIssue({ code: 'custom', message: 'Only an invalid-domain result may omit the normalized domain' });
			}
		}
	});

export type SmtpStarttlsResult = z.infer<typeof SmtpStarttlsResultSchema>;

/** Build the explicit fail-soft result used whenever no remote measurement exists. */
export function smtpNotAssessed(
	domain: string | null,
	reason: SmtpNotAssessedReason,
	now: () => string = () => new Date().toISOString(),
): SmtpStarttlsResult {
	return {
		schemaVersion: '1.0',
		probe: 'smtp_starttls',
		domain,
		status: 'not-assessed',
		outcome: reason === 'no_explicit_mx' ? 'no_explicit_mx' : 'not_assessed',
		observedAt: now(),
		nonScoring: true,
		targets: [],
		reason,
	};
}
