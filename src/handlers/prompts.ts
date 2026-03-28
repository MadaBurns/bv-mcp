// SPDX-License-Identifier: BUSL-1.1

/**
 * MCP Prompts handler for Blackveil DNS.
 * Provides pre-built workflows agents can discover and offer to users
 * via prompts/list + prompts/get.
 */

import { z } from 'zod';
import { DomainSchema, GradeSchema } from '../schemas/primitives';

/** MCP Prompt argument definition */
interface McpPromptArgument {
	name: string;
	description: string;
	required: boolean;
}

/** MCP Prompt definition */
interface McpPrompt {
	name: string;
	description: string;
	arguments: McpPromptArgument[];
}

/** MCP Prompt message */
interface McpPromptMessage {
	role: 'user' | 'assistant';
	content: {
		type: 'text';
		text: string;
	};
}

/** Zod schema for prompts that require only a domain argument. */
const DomainPromptArgs = z.object({
	domain: DomainSchema,
}).passthrough();

/** Zod schema for the policy-compliance-check prompt (domain + optional minimum_grade). */
const PolicyCompliancePromptArgs = z.object({
	domain: DomainSchema,
	minimum_grade: GradeSchema.optional(),
}).passthrough();

/** All MCP prompt definitions */
const PROMPTS: McpPrompt[] = [
	{
		name: 'full-security-audit',
		description: 'DNS & email security audit with remediation',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to audit (e.g. example.com)',
				required: true,
			},
		],
	},
	{
		name: 'email-auth-check',
		description: 'Email auth posture: SPF, DMARC, DKIM, MTA-STS',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to check (e.g. example.com)',
				required: true,
			},
		],
	},
	{
		name: 'policy-compliance-check',
		description: 'Check domain against security policy baseline',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to check (e.g. example.com)',
				required: true,
			},
			{
				name: 'minimum_grade',
				description: 'Min letter grade (default: "B")',
				required: false,
			},
		],
	},
	{
		name: 'remediation-workflow',
		description: 'Scan, plan fixes, generate DNS records',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to remediate (e.g. example.com)',
				required: true,
			},
		],
	},
	{
		name: 'email-hardening-guide',
		description: 'Email hardening plan with DNS record generation',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to harden (e.g. example.com)',
				required: true,
			},
		],
	},
	{
		name: 'provider-benchmark',
		description: 'Benchmark domain against email provider cohort',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to benchmark (e.g. example.com)',
				required: true,
			},
		],
	},
	{
		name: 'attack-surface-assessment',
		description: 'Spoofability, lookalikes, shadow domain analysis',
		arguments: [
			{
				name: 'domain',
				description: 'Domain to assess (e.g. example.com)',
				required: true,
			},
		],
	},
];

/** Prompt message templates keyed by prompt name */
function getPromptMessages(name: string, args: Record<string, string>): McpPromptMessage[] {
	const domain = args.domain;

	switch (name) {
		case 'full-security-audit':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use scan_domain on ${domain}, then explain_finding for each critical/high finding.
Summarize: score, grade, maturity stage, remediation priorities.`,
					},
				},
			];

		case 'email-auth-check':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use check_spf, check_dmarc, check_dkim, and check_mta_sts on ${domain}.
Use explain_finding for any failures.
Summarize spoofing/phishing protection status and steps to fix gaps.`,
					},
				},
			];

		case 'policy-compliance-check': {
			const grade = args.minimum_grade || 'B';
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use compare_baseline on ${domain} with baseline: {"grade":"${grade}","require_spf":true,"require_dmarc_enforce":true,"require_dkim":true,"max_critical_findings":0}
Report pass/fail with each violation and remediation needed.`,
					},
				},
			];
		}

		case 'remediation-workflow':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use generate_fix_plan on ${domain}. For the top 3 actions, generate records: generate_spf_record (SPF), generate_dmarc_record (DMARC), generate_dkim_config (DKIM), generate_mta_sts_policy (MTA-STS), or explain_finding (other).
Summarize: score, grade, exact DNS records to publish, verification steps.`,
					},
				},
			];

		case 'provider-benchmark':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use scan_domain on ${domain}, then get_benchmark for score distribution. If a provider is detected, use get_provider_insights.
Compare: percentile rank, provider cohort standing, top failing categories, improvements to rank higher.`,
					},
				},
			];

		case 'attack-surface-assessment':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use scan_domain, assess_spoofability, check_lookalikes, and check_shadow_domains on ${domain}.
Synthesize: spoofability risk, brand impersonation threats, shadow domain exposure, mitigation priorities.`,
					},
				},
			];

		case 'email-hardening-guide':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Use scan_domain on ${domain}. Based on maturity stage, build a hardening plan:
Stage 0-1: SPF + DMARC monitoring. Stage 2: DMARC enforcement + DKIM. Stage 3: MTA-STS + TLS-RPT. Stage 4: DNSSEC, DANE, BIMI.
Generate records via generate_spf_record, generate_dmarc_record (none->quarantine->reject), generate_dkim_config, generate_mta_sts_policy.
Include verification steps and DMARC report monitoring timeline.`,
					},
				},
			];

		default:
			throw new Error(`Invalid prompt name: ${name}`);
	}
}

/**
 * Handle the MCP prompts/list method.
 * Returns all available prompt definitions.
 */
export function handlePromptsList(): { prompts: McpPrompt[] } {
	return { prompts: PROMPTS };
}

/**
 * Handle the MCP prompts/get method.
 * Returns the messages for a specific prompt.
 */
export function handlePromptsGet(params: Record<string, unknown>): {
	description: string;
	messages: McpPromptMessage[];
} {
	const name = params.name;
	if (typeof name !== 'string') {
		throw new Error('Missing required parameter: name');
	}

	const prompt = PROMPTS.find((p) => p.name === name);
	if (!prompt) {
		throw new Error(`Invalid prompt name: ${name}`);
	}

	const rawArgs = (params.arguments ?? {}) as Record<string, unknown>;

	// Pick the appropriate schema based on prompt name
	const schema = name === 'policy-compliance-check' ? PolicyCompliancePromptArgs : DomainPromptArgs;
	const parsed = schema.safeParse(rawArgs);
	if (!parsed.success) {
		const firstIssue = parsed.error.issues[0];
		const field = firstIssue?.path.join('.') || 'arguments';
		throw new Error(`Invalid ${field}: ${firstIssue?.message ?? 'validation failed'}`);
	}

	const args: Record<string, string> = {};
	for (const [k, v] of Object.entries(parsed.data)) {
		if (typeof v === 'string') args[k] = v;
	}

	const messages = getPromptMessages(name, args);

	return {
		description: prompt.description,
		messages,
	};
}
