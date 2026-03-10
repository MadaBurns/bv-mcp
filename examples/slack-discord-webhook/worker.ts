/**
 * Blackveil DNS - Weekly Slack/Discord Webhook Reporter.
 *
 * Cloudflare Cron Trigger that scans a domain weekly and posts
 * a summary to Slack or Discord via incoming webhook.
 */

interface Env {
	DOMAIN: string;
	WEBHOOK_URL: string;
	MCP_ENDPOINT?: string;
}

const DEFAULT_ENDPOINT = 'https://dns-mcp.blackveilsecurity.com/mcp';

interface RpcResponse {
	result?: {
		content?: Array<{ text?: string }>;
	};
}

async function rpc(
	endpoint: string,
	method: string,
	params: Record<string, unknown>,
	sessionId?: string,
): Promise<{ result: RpcResponse['result']; sessionId?: string }> {
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		Accept: 'application/json',
	};
	if (sessionId) headers['Mcp-Session-Id'] = sessionId;

	const response = await fetch(endpoint, {
		method: 'POST',
		headers,
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
	});
	const body = (await response.json()) as RpcResponse;
	return {
		result: body.result,
		sessionId: response.headers.get('mcp-session-id') ?? sessionId,
	};
}

function parseScore(text: string): { score: string; grade: string; maturity: string } {
	const scoreMatch = text.match(/Overall Score:\s*(\d+\/100\s*\([^)]+\))/);
	const maturityMatch = text.match(/Email Security Maturity:\s*(Stage\s*\d+\s*[-]\s*[^\n]+)/);
	const gradeMatch = text.match(/Grade:\s*([A-F][+]?)/);

	return {
		score: scoreMatch?.[1] ?? 'unknown',
		grade: gradeMatch?.[1] ?? '?',
		maturity: maturityMatch?.[1] ?? 'unknown',
	};
}

function parseFindings(text: string): string[] {
	const findings: string[] = [];
	for (const match of text.matchAll(/\*\*\[(CRITICAL|HIGH)\]\*\*\s+([^\n]+)/g)) {
		findings.push(match[2].trim());
	}
	return findings;
}

function buildSlackPayload(domain: string, score: string, grade: string, maturity: string, findings: string[]): object {
	const color = grade.startsWith('A') ? '#4c1' : grade.startsWith('B') ? '#a4a61d' : '#e05d44';
	const findingsText = findings.length > 0 ? findings.map((finding) => `- ${finding}`).join('\n') : 'No high/critical findings.';

	return {
		attachments: [
			{
				color,
				blocks: [
					{
						type: 'header',
						text: { type: 'plain_text', text: `DNS Security Report: ${domain}` },
					},
					{
						type: 'section',
						fields: [
							{ type: 'mrkdwn', text: `*Score:*\n${score}` },
							{ type: 'mrkdwn', text: `*Maturity:*\n${maturity}` },
						],
					},
					{
						type: 'section',
						text: { type: 'mrkdwn', text: `*Top Findings:*\n${findingsText}` },
					},
					{
						type: 'context',
						elements: [
							{
								type: 'mrkdwn',
								text: `Scanned by <https://github.com/MadaBurns/bv-mcp|Blackveil DNS> at ${new Date().toISOString().slice(0, 10)}`,
							},
						],
					},
				],
			},
		],
	};
}

export default {
	async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
		const endpoint = env.MCP_ENDPOINT ?? DEFAULT_ENDPOINT;

		const initializeResult = await rpc(endpoint, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: { name: 'blackveil-webhook-reporter', version: '1.0.0' },
		});

		const scanResult = await rpc(
			endpoint,
			'tools/call',
			{ name: 'scan_domain', arguments: { domain: env.DOMAIN } },
			initializeResult.sessionId,
		);

		const text = scanResult.result?.content?.[0]?.text ?? '';
		const { score, grade, maturity } = parseScore(text);
		const findings = parseFindings(text);
		const payload = buildSlackPayload(env.DOMAIN, score, grade, maturity, findings);

		await fetch(env.WEBHOOK_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
		});
	},
};
