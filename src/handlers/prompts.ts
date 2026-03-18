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
