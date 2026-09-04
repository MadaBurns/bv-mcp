// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import { createEvidenceSnapshot, verifyEvidenceSnapshot, type EvidenceSnapshot } from './evidence';
import { DEFAULT_MCP_ENDPOINT, McpClientError, McpHttpClient, type ToolCallResult } from './mcp-http-client';
import { BatchResultSchema, CheckResultSchema, DriftResultSchema, PolicyResultSchema, ScanResultSchema, type ScanResult } from './schemas';

export type CliExitCode = 0 | 1 | 2 | 3 | 4;
export type CliOutputFormat = 'human' | 'json' | 'ndjson' | 'evidence';

export interface CliIo {
	readTextFile(path: string): Promise<string>;
	writeTextFile(path: string, content: string, overwrite: boolean): Promise<void>;
	stdout(text: string): void;
	stderr(text: string): void;
}

export interface CliDependencies {
	io: CliIo;
	env?: Record<string, string | undefined>;
	fetchFn?: typeof fetch;
	now?: () => Date;
}

class CliUsageError extends Error {}
class CliVerificationError extends Error {}

const HELP = `BlackVeil hosted DNS security CLI

Usage:
  blackveil scan <domain> [--format human|json|ndjson|evidence] [--out <file>] [--force-refresh]
                         [--fail-below <0-100> | --policy <file>]
  blackveil check <name> <domain> [--format human|json|ndjson|evidence] [--out <file>] [--force-refresh]
  blackveil batch --file <domains.txt> [--format human|json|ndjson|evidence] [--out <file>] [--force-refresh]
                                      [--fail-below <0-100> | --policy <file>]
  blackveil policy <domain> (--fail-below <0-100> | --policy <file>) [--format human|json|ndjson|evidence]
  blackveil drift save <domain> --out <file> [--force-refresh] [--force]
  blackveil drift compare <domain> --baseline <evidence.json> [--format human|json|ndjson|evidence]
  blackveil evidence verify <evidence.json> [--format human|json]

Environment:
  BLACKVEIL_API_KEY   Optional bearer credential. API keys are never accepted on the command line.
  BLACKVEIL_MCP_URL   Optional MCP endpoint. HTTPS is required except for loopback development.

Exit codes:
  0 completed/pass; 1 verified policy or integrity failure; 2 usage/input;
  3 auth/quota/transport/protocol/tool error; 4 ungraded/inconclusive/incomplete.
`;

type ParsedArgs = {
	positionals: string[];
	values: Map<string, string>;
	flags: Set<string>;
};

const VALUE_OPTIONS = new Set(['--format', '--out', '--file', '--policy', '--fail-below', '--baseline']);
const BOOLEAN_OPTIONS = new Set(['--force-refresh', '--force']);

function parseArgs(args: string[]): ParsedArgs {
	const parsed: ParsedArgs = { positionals: [], values: new Map(), flags: new Set() };
	for (let index = 0; index < args.length; index += 1) {
		const token = args[index];
		if (!token) continue;
		if (VALUE_OPTIONS.has(token)) {
			if (parsed.values.has(token)) throw new CliUsageError(`Duplicate option ${token}`);
			const value = args[++index];
			if (!value || value.startsWith('--')) throw new CliUsageError(`Missing value for ${token}`);
			parsed.values.set(token, value);
			continue;
		}
		if (BOOLEAN_OPTIONS.has(token)) {
			if (parsed.flags.has(token)) throw new CliUsageError(`Duplicate option ${token}`);
			parsed.flags.add(token);
			continue;
		}
		if (token.startsWith('-')) throw new CliUsageError(`Unknown option ${token}`);
		parsed.positionals.push(token);
	}
	return parsed;
}

function assertOptions(parsed: ParsedArgs, allowedValues: string[], allowedFlags: string[]): void {
	for (const option of parsed.values.keys()) {
		if (!allowedValues.includes(option)) throw new CliUsageError(`Option ${option} is not valid for this command`);
	}
	for (const option of parsed.flags) {
		if (!allowedFlags.includes(option)) throw new CliUsageError(`Option ${option} is not valid for this command`);
	}
}

function outputFormat(parsed: ParsedArgs, allowed: readonly CliOutputFormat[] = ['human', 'json', 'ndjson', 'evidence']): CliOutputFormat {
	const value = parsed.values.get('--format') ?? 'human';
	if (!allowed.includes(value as CliOutputFormat)) throw new CliUsageError(`Invalid output format ${value}`);
	return value as CliOutputFormat;
}

function requiredSinglePosition(parsed: ParsedArgs, label: string): string {
	if (parsed.positionals.length !== 1 || !parsed.positionals[0]) throw new CliUsageError(`Expected exactly one ${label}`);
	return parsed.positionals[0];
}

function parseScoreFloor(raw: string): number {
	const value = Number(raw);
	if (!Number.isFinite(value) || value < 0 || value > 100) throw new CliUsageError('--fail-below must be a number from 0 to 100');
	return value;
}

async function parseJsonFile(io: CliIo, path: string): Promise<unknown> {
	let text: string;
	try {
		text = await io.readTextFile(path);
	} catch (error) {
		const message = error instanceof Error ? error.message : 'read failed';
		throw new CliUsageError(`Could not read ${path}: ${message}`);
	}
	try {
		return JSON.parse(text);
	} catch {
		throw new CliUsageError(`${path} does not contain valid JSON`);
	}
}

async function loadPolicy(parsed: ParsedArgs, io: CliIo): Promise<Record<string, unknown> | undefined> {
	const policyPath = parsed.values.get('--policy');
	const floor = parsed.values.get('--fail-below');
	if (policyPath && floor) throw new CliUsageError('Use either --policy or --fail-below, not both');
	if (floor !== undefined) return { score: parseScoreFloor(floor) };
	if (!policyPath) return undefined;
	const value = await parseJsonFile(io, policyPath);
	if (!value || typeof value !== 'object' || Array.isArray(value)) throw new CliUsageError('Policy JSON must be an object');
	return value as Record<string, unknown>;
}

function requireStructured(result: ToolCallResult, tool: string): Record<string, unknown> {
	if (!result.structuredContent) throw new McpClientError(`MCP tool ${tool} omitted structuredContent`, 'protocol');
	return result.structuredContent;
}

function toolText(result: ToolCallResult): string {
	const text = result.content.find((item) => item.type === 'text' && typeof item.text === 'string')?.text;
	if (!text) throw new McpClientError('MCP tool result omitted human-readable text', 'protocol');
	return text;
}

function toolErrorText(result: ToolCallResult): string {
	return result.content
		.filter((item) => item.type === 'text' && typeof item.text === 'string')
		.map((item) => item.text)
		.join('\n');
}

function classifyToolError(result: ToolCallResult): CliExitCode | undefined {
	if (!result.isError) return undefined;
	const message = toolErrorText(result);
	if (/Invalid baseline|could not read|valid JSON/i.test(message)) return 2;
	if (/never graded|could not be scored|nothing to measure/i.test(message)) return 4;
	return 3;
}

function scanExit(scan: ScanResult): CliExitCode {
	return !scan.measured || scan.score === null || scan.grade === null || scan.evidenceInsufficient || scan.error ? 4 : 0;
}

function policyExit(value: z.infer<typeof PolicyResultSchema>): CliExitCode {
	return value.passed === null ? 4 : value.passed ? 0 : 1;
}

/** System errors outrank incomplete evidence, which outranks measured policy failure. */
export function combineBatchExitCodes(codes: readonly CliExitCode[]): CliExitCode {
	if (codes.includes(3)) return 3;
	if (codes.includes(4)) return 4;
	if (codes.includes(1)) return 1;
	if (codes.includes(2)) return 2;
	return 0;
}

function ndjson(value: Record<string, unknown>): string {
	const results = value.results;
	if (Array.isArray(results)) return results.map((entry) => JSON.stringify(entry)).join('\n');
	return JSON.stringify(value);
}

async function renderedOutput(args: {
	result: ToolCallResult;
	format: CliOutputFormat;
	tool: string;
	client: McpHttpClient;
	now: () => Date;
}): Promise<string> {
	if (args.format === 'human') return toolText(args.result);
	const structured = requireStructured(args.result, args.tool);
	if (args.format === 'json') return JSON.stringify(structured, null, 2);
	if (args.format === 'ndjson') return ndjson(structured);
	const serverInfo = args.client.serverInfo;
	if (!serverInfo) throw new McpClientError('MCP client has no server provenance', 'protocol');
	const evidence = await createEvidenceSnapshot({
		capturedAt: args.now().toISOString(),
		serverName: serverInfo.name,
		serverVersion: serverInfo.version,
		endpointOrigin: args.client.endpointOrigin,
		tool: args.tool,
		result: structured,
	});
	return JSON.stringify(evidence, null, 2);
}

async function emit(io: CliIo, parsed: ParsedArgs, content: string): Promise<void> {
	const out = parsed.values.get('--out');
	if (!out) {
		io.stdout(`${content}\n`);
		return;
	}
	try {
		await io.writeTextFile(out, `${content}\n`, parsed.flags.has('--force'));
	} catch (error) {
		const message = error instanceof Error ? error.message : 'write failed';
		throw new CliUsageError(`Could not write ${out}: ${message}`);
	}
	io.stderr(`Wrote ${out}\n`);
}

function createClient(deps: CliDependencies): McpHttpClient {
	return new McpHttpClient({
		endpoint: deps.env?.BLACKVEIL_MCP_URL ?? DEFAULT_MCP_ENDPOINT,
		apiKey: deps.env?.BLACKVEIL_API_KEY,
		fetchFn: deps.fetchFn,
	});
}

async function connectedClient(deps: CliDependencies): Promise<McpHttpClient> {
	const client = createClient(deps);
	await client.connect();
	return client;
}

async function callPolicy(client: McpHttpClient, domain: string, baseline: Record<string, unknown>) {
	const result = await client.callTool('compare_baseline', { domain, baseline, format: 'full' });
	const errorExit = classifyToolError(result);
	if (errorExit !== undefined) return { result, exit: errorExit };
	const parsed = PolicyResultSchema.safeParse(requireStructured(result, 'compare_baseline'));
	if (!parsed.success) throw new McpClientError('compare_baseline returned malformed structuredContent', 'protocol');
	return { result, exit: policyExit(parsed.data) };
}

async function runScan(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--format', '--out', '--policy', '--fail-below'], ['--force-refresh', '--force']);
	const domain = requiredSinglePosition(parsed, 'domain');
	const format = outputFormat(parsed);
	const baseline = await loadPolicy(parsed, deps.io);
	const client = await connectedClient(deps);
	const result = await client.callTool('scan_domain', {
		domain,
		format: 'full',
		...(parsed.flags.has('--force-refresh') ? { force_refresh: true } : {}),
	});
	const errorExit = classifyToolError(result);
	if (errorExit !== undefined) return errorExit;
	const structured = ScanResultSchema.safeParse(requireStructured(result, 'scan_domain'));
	if (!structured.success) throw new McpClientError('scan_domain returned malformed structuredContent', 'protocol');
	await emit(deps.io, parsed, await renderedOutput({ result, format, tool: 'scan_domain', client, now: deps.now ?? (() => new Date()) }));
	const scanCode = scanExit(structured.data);
	if (scanCode !== 0 || !baseline) return scanCode;
	return (await callPolicy(client, domain, baseline)).exit;
}

async function runCheck(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--format', '--out'], ['--force-refresh', '--force']);
	if (parsed.positionals.length !== 2) throw new CliUsageError('Expected a check name and one domain');
	const [rawName, domain] = parsed.positionals;
	if (!rawName || !domain) throw new CliUsageError('Expected a check name and one domain');
	const toolName = rawName.startsWith('check_') ? rawName : `check_${rawName.replaceAll('-', '_')}`;
	if (!/^check_[a-z0-9_]+$/.test(toolName)) throw new CliUsageError('Invalid check name');
	const format = outputFormat(parsed);
	const client = await connectedClient(deps);
	const tools = await client.listTools();
	const tool = tools.find((entry) => entry.name === toolName);
	if (!tool || tool.annotations?.readOnlyHint !== true || tool.outputSchema === undefined) {
		throw new CliUsageError(`${toolName} is not a public read-only CheckResult tool`);
	}
	const result = await client.callTool(toolName, {
		domain,
		format: 'full',
		...(parsed.flags.has('--force-refresh') ? { force_refresh: true } : {}),
	});
	const errorExit = classifyToolError(result);
	if (errorExit !== undefined) return errorExit;
	const structured = CheckResultSchema.safeParse(requireStructured(result, toolName));
	if (!structured.success) throw new McpClientError(`${toolName} returned malformed CheckResult structuredContent`, 'protocol');
	await emit(deps.io, parsed, await renderedOutput({ result, format, tool: toolName, client, now: deps.now ?? (() => new Date()) }));
	return structured.data.partial ? 4 : 0;
}

async function readDomains(io: CliIo, path: string): Promise<string[]> {
	let text: string;
	try {
		text = await io.readTextFile(path);
	} catch (error) {
		const message = error instanceof Error ? error.message : 'read failed';
		throw new CliUsageError(`Could not read ${path}: ${message}`);
	}
	const domains = text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith('#'));
	if (domains.length < 1 || domains.length > 10) throw new CliUsageError('Batch file must contain 1 to 10 domains');
	return domains;
}

async function runBatch(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--format', '--out', '--file', '--policy', '--fail-below'], ['--force-refresh', '--force']);
	if (parsed.positionals.length !== 0) throw new CliUsageError('Batch accepts domains only through --file');
	const file = parsed.values.get('--file');
	if (!file) throw new CliUsageError('Batch requires --file');
	const format = outputFormat(parsed);
	const domains = await readDomains(deps.io, file);
	const baseline = await loadPolicy(parsed, deps.io);
	const client = await connectedClient(deps);
	const result = await client.callTool('batch_scan', {
		domains,
		format: 'full',
		...(parsed.flags.has('--force-refresh') ? { force_refresh: true } : {}),
	});
	const errorExit = classifyToolError(result);
	if (errorExit !== undefined) return errorExit;
	const structured = BatchResultSchema.safeParse(requireStructured(result, 'batch_scan'));
	if (!structured.success) throw new McpClientError('batch_scan returned malformed structuredContent', 'protocol');
	await emit(deps.io, parsed, await renderedOutput({ result, format, tool: 'batch_scan', client, now: deps.now ?? (() => new Date()) }));

	const codes: CliExitCode[] = structured.data.results.map(scanExit);
	if (baseline) {
		for (const scan of structured.data.results) {
			if (scanExit(scan) !== 0) continue;
			codes.push((await callPolicy(client, scan.domain, baseline)).exit);
		}
	}
	return combineBatchExitCodes(codes);
}

async function runPolicy(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--format', '--out', '--policy', '--fail-below'], ['--force']);
	const domain = requiredSinglePosition(parsed, 'domain');
	const baseline = await loadPolicy(parsed, deps.io);
	if (!baseline) throw new CliUsageError('Policy requires --policy or --fail-below');
	const format = outputFormat(parsed);
	const client = await connectedClient(deps);
	const evaluated = await callPolicy(client, domain, baseline);
	if (evaluated.exit === 2 || evaluated.exit === 3) return evaluated.exit;
	await emit(
		deps.io,
		parsed,
		await renderedOutput({ result: evaluated.result, format, tool: 'compare_baseline', client, now: deps.now ?? (() => new Date()) }),
	);
	return evaluated.exit;
}

function driftBaselineFromScan(scan: ScanResult): Record<string, unknown> {
	if (scan.score === null || scan.grade === null) throw new CliUsageError('An ungraded scan cannot be used as a drift baseline');
	return {
		overall: scan.score,
		grade: scan.grade,
		categoryScores: Object.fromEntries(Object.entries(scan.categoryScores).filter((entry): entry is [string, number] => entry[1] !== null)),
		findings: scan.findings,
	};
}

async function runDriftSave(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--out'], ['--force-refresh', '--force']);
	const domain = requiredSinglePosition(parsed, 'domain');
	if (!parsed.values.get('--out')) throw new CliUsageError('drift save requires --out');
	const client = await connectedClient(deps);
	const result = await client.callTool('scan_domain', {
		domain,
		format: 'full',
		...(parsed.flags.has('--force-refresh') ? { force_refresh: true } : {}),
	});
	const errorExit = classifyToolError(result);
	if (errorExit !== undefined) return errorExit;
	const structured = ScanResultSchema.safeParse(requireStructured(result, 'scan_domain'));
	if (!structured.success) throw new McpClientError('scan_domain returned malformed structuredContent', 'protocol');
	await emit(
		deps.io,
		parsed,
		await renderedOutput({ result, format: 'evidence', tool: 'scan_domain', client, now: deps.now ?? (() => new Date()) }),
	);
	return scanExit(structured.data);
}

async function loadVerifiedEvidence(io: CliIo, path: string): Promise<EvidenceSnapshot> {
	const raw = await parseJsonFile(io, path);
	let verification;
	try {
		verification = await verifyEvidenceSnapshot(raw);
	} catch (error) {
		const message = error instanceof Error ? error.message : 'schema validation failed';
		throw new CliUsageError(`Invalid evidence snapshot: ${message}`);
	}
	if (!verification.valid) throw new CliVerificationError('Evidence snapshot integrity verification failed');
	return verification.snapshot;
}

async function runDriftCompare(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--format', '--out', '--baseline'], ['--force']);
	const domain = requiredSinglePosition(parsed, 'domain');
	const baselinePath = parsed.values.get('--baseline');
	if (!baselinePath) throw new CliUsageError('drift compare requires --baseline');
	const evidence = await loadVerifiedEvidence(deps.io, baselinePath);
	if (evidence.source.tool !== 'scan_domain') throw new CliUsageError('Drift baseline evidence must come from scan_domain');
	const scan = ScanResultSchema.safeParse(evidence.result);
	if (!scan.success) throw new CliUsageError('Drift baseline does not contain a valid scan result');
	if (scan.data.domain !== domain) throw new CliUsageError('Drift baseline domain does not match the requested domain');
	const baseline = driftBaselineFromScan(scan.data);
	const format = outputFormat(parsed);
	const client = await connectedClient(deps);
	const result = await client.callTool('analyze_drift', { domain, baseline: JSON.stringify(baseline), format: 'full' });
	const errorExit = classifyToolError(result);
	if (errorExit !== undefined) return errorExit;
	const structured = DriftResultSchema.safeParse(requireStructured(result, 'analyze_drift'));
	if (!structured.success) throw new McpClientError('analyze_drift returned malformed structuredContent', 'protocol');
	await emit(deps.io, parsed, await renderedOutput({ result, format, tool: 'analyze_drift', client, now: deps.now ?? (() => new Date()) }));
	return structured.data.classification === 'inconclusive' ? 4 : 0;
}

async function runEvidenceVerify(parsed: ParsedArgs, deps: CliDependencies): Promise<CliExitCode> {
	assertOptions(parsed, ['--format'], []);
	const path = requiredSinglePosition(parsed, 'evidence file');
	const format = outputFormat(parsed, ['human', 'json']);
	const raw = await parseJsonFile(deps.io, path);
	let verification;
	try {
		verification = await verifyEvidenceSnapshot(raw);
	} catch (error) {
		const message = error instanceof Error ? error.message : 'schema validation failed';
		throw new CliUsageError(`Invalid evidence snapshot: ${message}`);
	}
	if (format === 'json') {
		deps.io.stdout(
			`${JSON.stringify({ valid: verification.valid, expectedDigest: verification.expectedDigest, actualDigest: verification.actualDigest }, null, 2)}\n`,
		);
	} else {
		deps.io.stdout(
			verification.valid
				? `VALID ${verification.actualDigest}\n`
				: `INVALID expected ${verification.expectedDigest} but computed ${verification.actualDigest}\n`,
		);
	}
	return verification.valid ? 0 : 1;
}

/** Execute one CLI invocation without mutating process globals. */
export async function runCli(argv: string[], deps: CliDependencies): Promise<CliExitCode> {
	if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
		deps.io.stdout(HELP);
		return 0;
	}

	try {
		const [command, ...rest] = argv;
		const parsed = parseArgs(rest);
		switch (command) {
			case 'scan':
				return await runScan(parsed, deps);
			case 'check':
				return await runCheck(parsed, deps);
			case 'batch':
				return await runBatch(parsed, deps);
			case 'policy':
				return await runPolicy(parsed, deps);
			case 'drift': {
				const [subcommand, ...subcommandArgs] = rest;
				if (!subcommand) throw new CliUsageError('drift requires save or compare');
				const driftParsed = parseArgs(subcommandArgs);
				if (subcommand === 'save') return await runDriftSave(driftParsed, deps);
				if (subcommand === 'compare') return await runDriftCompare(driftParsed, deps);
				throw new CliUsageError('drift requires save or compare');
			}
			case 'evidence': {
				const [subcommand, ...subcommandArgs] = rest;
				if (subcommand !== 'verify') throw new CliUsageError('evidence requires verify');
				return await runEvidenceVerify(parseArgs(subcommandArgs), deps);
			}
			default:
				throw new CliUsageError(`Unknown command ${command}`);
		}
	} catch (error) {
		if (error instanceof CliVerificationError) {
			deps.io.stderr(`${error.message}\n`);
			return 1;
		}
		if (error instanceof CliUsageError) {
			deps.io.stderr(`${error.message}\nRun blackveil --help for usage.\n`);
			return 2;
		}
		if (error instanceof McpClientError) {
			deps.io.stderr(`${error.message}\n`);
			return 3;
		}
		deps.io.stderr(`${error instanceof Error ? error.message : 'Unexpected CLI failure'}\n`);
		return 3;
	}
}
