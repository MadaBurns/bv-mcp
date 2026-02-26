/**
 * MCP Tools handler for the BLACKVEIL Scanner.
 * Defines all tool schemas and dispatches tools/call requests
 * to the appropriate BLACKVEIL Scanner check functions.
 *
 * Handles JSON-RPC methods: tools/list, tools/call
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import { validateDomain, sanitizeDomain, mcpError, mcpText } from '../lib/sanitize';
import type { CheckCategory, CheckResult, Severity } from '../lib/scoring';
import { cacheGet, cacheSet } from '../lib/cache';
import { checkSpf } from '../tools/check-spf';
import { checkDmarc } from '../tools/check-dmarc';
import { checkDkim } from '../tools/check-dkim';
import { checkDnssec } from '../tools/check-dnssec';
import { checkSsl } from '../tools/check-ssl';
import { checkMtaSts } from '../tools/check-mta-sts';
import { checkNs } from '../tools/check-ns';
import { checkCaa } from '../tools/check-caa';
import { scanDomain, formatScanReport } from '../tools/scan-domain';
import { explainFinding, formatExplanation } from '../tools/explain-finding';
import { logEvent, logError } from '../lib/log';

/** MCP Tool definition */
interface McpTool {
	name: string;
	description: string;
	inputSchema: {
		type: 'object';
		properties: Record<string, unknown>;
		required: string[];
	};
}

/** MCP content item */
interface McpContent {
	type: 'text';
	text: string;
}

/** MCP tools/call result */
interface McpToolResult {
	content: McpContent[];
	isError?: boolean;
}

/** Domain-only input schema shared by most tools */
const DOMAIN_INPUT_SCHEMA = {
	type: 'object' as const,
	properties: {
		domain: {
			type: 'string',
			description: 'The domain name to check (e.g., example.com)',
		},
	},
	required: ['domain'],
};

/** All MCP tool definitions */
const TOOLS: McpTool[] = [
	{
		name: 'check_mx',
		description: 'Check MX (Mail Exchange) records for a domain. Validates presence and quality of MX records, assesses outbound email usage.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_spf',
		description:
			'Check SPF (Sender Policy Framework) records for a domain. Validates SPF TXT records for proper syntax, mechanisms, and policy.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dmarc',
		description:
			'Check DMARC (Domain-based Message Authentication) records for a domain. Validates _dmarc TXT records for policy configuration.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dkim',
		description: 'Check DKIM (DomainKeys Identified Mail) records for a domain. Probes common selectors for DKIM key records.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name to check (e.g., example.com)',
				},
				selector: {
					type: 'string',
					description: "Optional: specific DKIM selector to check (e.g., 'google', 'selector1'). If omitted, common selectors are probed.",
				},
			},
			required: ['domain'],
		},
	},
	{
		name: 'check_dnssec',
		description:
			'Check DNSSEC (DNS Security Extensions) status for a domain. Verifies if DNS responses are cryptographically signed and validated.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ssl',
		description: 'Check SSL/TLS certificate configuration for a domain. Validates certificate status and configuration.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_mta_sts',
		description: 'Check MTA-STS (Mail Transfer Agent Strict Transport Security) for a domain. Validates _mta-sts TXT records and policy.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ns',
		description: 'Check name server (NS) configuration for a domain. Analyzes NS records for redundancy, diversity, and proper delegation.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_caa',
		description:
			'Check CAA (Certificate Authority Authorization) records for a domain. Validates which CAs are authorized to issue certificates.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'scan_domain',
		description:
			'Run a comprehensive DNS security scan on a domain. Executes all checks (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA) in parallel and returns an overall security score and grade.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'explain_finding',
		description: 'Get a plain-language explanation of a DNS security finding and recommended remediation steps.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				checkType: {
					type: 'string',
					description: "The check type (e.g. 'SPF', 'DMARC', 'DKIM', 'DNSSEC', 'SSL', 'MTA_STS')",
				},
				status: {
					type: 'string',
					enum: ['pass', 'fail', 'warning'],
					description: 'The check status',
				},
				details: {
					type: 'string',
					description: 'Optional details from the check result',
				},
			},
			required: ['checkType', 'status'],
		},
	},
];

/**
 * Handle the MCP tools/list method.
 * Returns all available tool definitions.
 */
export function handleToolsList(): { tools: McpTool[] } {
	return { tools: TOOLS };
}

/**
 * Validate a domain parameter from tool arguments.
 * Returns the sanitized domain or throws with an MCP error message.
 */
function extractAndValidateDomain(args: Record<string, unknown>): string {
	const domain = args.domain;
	if (typeof domain !== 'string' || domain.trim().length === 0) {
		throw new Error('Missing required parameter: domain');
	}
	const validation = validateDomain(domain);
	if (!validation.valid) {
		throw new Error(validation.error ?? 'Invalid domain');
	}
	return sanitizeDomain(domain);
}

/**
 * Format a CheckResult into MCP text content.
 */
function formatCheckResult(result: CheckResult): string {
	const lines: string[] = [];
	lines.push(`## ${result.category.toUpperCase()} Check`);
	lines.push(`**Status:** ${result.passed ? '✅ Passed' : '❌ Failed'}`);
	lines.push(`**Score:** ${result.score}/100`);
	lines.push('');

	if (result.findings.length > 0) {
		lines.push('### Findings');
		for (const finding of result.findings) {
			const icon =
				finding.severity === 'info'
					? 'ℹ️'
					: finding.severity === 'low'
						? '⚠️'
						: finding.severity === 'medium'
							? '🔶'
							: finding.severity === 'high'
								? '🔴'
								: '🚨';
			lines.push(`- ${icon} **[${finding.severity.toUpperCase()}]** ${finding.title}`);
			lines.push(`  ${finding.detail}`);
		}
	}

	return lines.join('\n');
}

async function runCachedToolCheck(
	domain: string,
	checkName: string,
	run: () => Promise<CheckResult>,
	cacheKV?: KVNamespace,
): Promise<CheckResult> {
	const cacheKey = `cache:${domain}:check:${checkName}`;
	const cached = await cacheGet<CheckResult>(cacheKey, cacheKV);
	if (cached) {
		return cached;
	}

	const result = await run();
	await cacheSet(cacheKey, result, cacheKV);
	return result;
}

/**
 * Handle the MCP tools/call method.
 * Dispatches to the appropriate tool function based on the tool name.
 *
 * @param params - Tool call parameters (name and arguments)
 * @param scanCacheKV - Optional KV namespace for scan result caching
 */
export async function handleToolsCall(
       params: {
	       name: string;
	       arguments?: Record<string, unknown>;
       },
       scanCacheKV?: KVNamespace,
): Promise<McpToolResult> {
       const { name } = params;
       const args = params.arguments ?? {};
       const startTime = Date.now();
       let domain: string | undefined;
       let logResult: string | undefined;
       let logDetails: unknown;
       try {
	       // Dispatch to the appropriate tool
	       switch (name) {
		       case 'check_mx': {
			       domain = extractAndValidateDomain(args);
			       const { checkMx } = await import('../tools/check-mx');
			       const result = await runCachedToolCheck(domain, 'mx', () => checkMx(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_spf': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'spf', () => checkSpf(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_dmarc': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'dmarc', () => checkDmarc(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_dkim': {
			       domain = extractAndValidateDomain(args);
			       let selector: string | undefined;
			       if (typeof args.selector === 'string' && args.selector.trim().length > 0) {
				       const sel = args.selector.trim().toLowerCase();
				       // Validate selector as a DNS label: alphanumeric + hyphens, max 63 chars
				       if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(sel) || sel.length > 63) {
					       logError('Invalid DKIM selector', {
						       tool: name,
						       domain,
						       details: { selector: sel },
						       severity: 'warn',
					       });
					       return {
						       content: [mcpError('Invalid DKIM selector: must be a valid DNS label (alphanumeric and hyphens, max 63 chars)')],
						       isError: true,
					       };
				       }
				       selector = sel;
			       }
			       const result = await runCachedToolCheck(
				       domain,
				       selector ? `dkim:${selector}` : 'dkim',
				       () => checkDkim(domain, selector),
				       scanCacheKV,
			       );
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_dnssec': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'dnssec', () => checkDnssec(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_ssl': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'ssl', () => checkSsl(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_mta_sts': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'mta_sts', () => checkMtaSts(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_ns': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'ns', () => checkNs(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'check_caa': {
			       domain = extractAndValidateDomain(args);
			       const result = await runCachedToolCheck(domain, 'caa', () => checkCaa(domain), scanCacheKV);
			       logResult = result.passed ? 'pass' : 'fail';
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: result.passed ? 'info' : 'warn',
			       });
			       return { content: [mcpText(formatCheckResult(result))] };
		       }
		       case 'scan_domain': {
			       domain = extractAndValidateDomain(args);
			       const result = await scanDomain(domain, scanCacheKV);
			       logResult = result.grade;
			       logDetails = result;
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       domain,
				       result: logResult,
				       details: logDetails,
				       durationMs: Date.now() - startTime,
				       severity: 'info',
			       });
			       return { content: [mcpText(formatScanReport(result))] };
		       }
		       case 'explain_finding': {
			       const checkType = args.checkType;
			       const status = args.status;
			       if (typeof checkType !== 'string' || typeof status !== 'string') {
				       logError('Missing required parameters: checkType and status', {
					       tool: name,
					       details: args,
					       severity: 'warn',
				       });
				       return { content: [mcpError('Missing required parameters: checkType and status')], isError: true };
			       }
			       const details = typeof args.details === 'string' ? args.details : undefined;
			       const result = explainFinding(checkType, status, details);
			       logEvent({
				       timestamp: new Date().toISOString(),
				       tool: name,
				       result: status,
				       details: { checkType, details },
				       durationMs: Date.now() - startTime,
				       severity: 'info',
			       });
			       return { content: [mcpText(formatExplanation(result))] };
		       }
		       default:
			       logError(`Unknown tool: ${name}`, {
				       tool: name,
				       details: args,
				       severity: 'error',
			       });
			       return {
				       content: [mcpError(`Unknown tool: ${name}`)],
				       isError: true,
			       };
	       }
       } catch (err) {
	       // Only pass through known validation errors; sanitize unexpected errors
	       const isValidationError =
		       err instanceof Error &&
		       (err.message.startsWith('Missing required') ||
			       err.message.startsWith('Invalid') ||
			       err.message.startsWith('Domain validation failed'));
	       const message = isValidationError ? err.message : 'An unexpected error occurred';
	       logError(err instanceof Error ? err : String(err), {
		       tool: name,
		       domain,
		       details: args,
		       severity: 'error',
	       });
	       return { content: [mcpError(message)], isError: true };
       }
}
