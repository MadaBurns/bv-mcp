// SPDX-License-Identifier: BUSL-1.1

/**
 * MCP Prompts handler for Blackveil DNS.
 * Provides pre-built workflows agents can discover and offer to users
 * via prompts/list + prompts/get.
 */

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

/** All MCP prompt definitions */
const PROMPTS: McpPrompt[] = [
	{
		name: 'full-security-audit',
		description: 'Run a comprehensive DNS and email security audit with remediation guidance',
		arguments: [
			{
				name: 'domain',
				description: 'The domain to audit (e.g., example.com)',
				required: true,
			},
		],
	},
	{
		name: 'email-auth-check',
		description: 'Check email authentication posture — SPF, DMARC, DKIM, and MTA-STS',
		arguments: [
			{
				name: 'domain',
				description: 'The domain to check (e.g., example.com)',
				required: true,
			},
		],
	},
	{
		name: 'policy-compliance-check',
		description: 'Compare a domain against security policy baselines for compliance enforcement',
		arguments: [
			{
				name: 'domain',
				description: 'The domain to check (e.g., example.com)',
				required: true,
			},
			{
				name: 'minimum_grade',
				description: 'Minimum acceptable letter grade (default: "B")',
				required: false,
			},
		],
	},
	{
		name: 'remediation-workflow',
		description: 'Guided remediation: scan, generate fix plan, produce DNS records for top issues',
		arguments: [
			{
				name: 'domain',
				description: 'The domain to remediate (e.g., example.com)',
				required: true,
			},
		],
	},
	{
		name: 'email-hardening-guide',
		description: 'Step-by-step email security hardening with record generation and verification',
		arguments: [
			{
				name: 'domain',
				description: 'The domain to harden (e.g., example.com)',
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
						text: `Run a comprehensive DNS and email security audit on ${domain}.

1. Start by running scan_domain on ${domain} to get the overall security score, grade, and all findings.
2. For any critical or high severity findings, run explain_finding to get plain-language remediation guidance.
3. Summarize the results with:
   - Overall score and grade
   - Maturity stage
   - Critical and high findings with remediation steps
   - Prioritized action plan for improving the security posture`,
					},
				},
			];

		case 'email-auth-check':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Check the email authentication posture for ${domain}.

1. Run check_spf to validate SPF records and identify trust surface exposure.
2. Run check_dmarc to assess DMARC policy enforcement and reporting configuration.
3. Run check_dkim to verify DKIM key presence and strength.
4. Run check_mta_sts to check SMTP transport encryption enforcement.
5. For any failures, run explain_finding to get remediation guidance.
6. Summarize whether ${domain} is protected against email spoofing and phishing, with specific steps to fix any gaps.`,
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
						text: `Check if ${domain} meets security policy compliance requirements.

Run compare_baseline on ${domain} with the following baseline:
{
  "grade": "${grade}",
  "require_spf": true,
  "require_dmarc_enforce": true,
  "require_dkim": true,
  "max_critical_findings": 0
}

Report whether the domain passes or fails compliance, listing each specific violation and the remediation needed to achieve compliance.`,
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
						text: `Run a guided remediation workflow for ${domain}.

1. Run generate_fix_plan on ${domain} to get a prioritized list of remediation actions.
2. For the top 3 highest-priority actions:
   a. If SPF-related: run generate_spf_record to produce a corrected SPF record.
   b. If DMARC-related: run generate_dmarc_record to produce a DMARC record.
   c. If DKIM-related: run generate_dkim_config to get provider-specific setup instructions.
   d. If MTA-STS-related: run generate_mta_sts_policy to generate the policy.
   e. For other issues: run explain_finding to get remediation guidance.
3. Present a summary with:
   - Current score and grade
   - Each action with the exact DNS record to publish
   - Verification steps to confirm the changes worked`,
					},
				},
			];

		case 'email-hardening-guide':
			return [
				{
					role: 'user',
					content: {
						type: 'text',
						text: `Create an email security hardening guide for ${domain}.

1. Run scan_domain on ${domain} to assess the current security posture.
2. Based on the maturity stage, create a step-by-step hardening plan:
   - Stage 0-1 (Unprotected/Basic): Start with SPF and DMARC monitoring
   - Stage 2 (Monitoring): Move to DMARC enforcement and add DKIM
   - Stage 3 (Enforcing): Add MTA-STS and TLS-RPT
   - Stage 4 (Hardened): Consider DNSSEC, DANE, and BIMI
3. For each step, generate the appropriate DNS records:
   - generate_spf_record for SPF
   - generate_dmarc_record for DMARC (start with p=none, then quarantine, then reject)
   - generate_dkim_config for DKIM
   - generate_mta_sts_policy for MTA-STS
4. Provide a verification checklist:
   - How to test each change
   - What to monitor in DMARC reports
   - Timeline for moving from monitoring to enforcement`,
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

	const args = (params.arguments as Record<string, string>) ?? {};
	const messages = getPromptMessages(name, args);

	return {
		description: prompt.description,
		messages,
	};
}
