// SPDX-License-Identifier: BUSL-1.1

import { handleToolsList, handleToolsCall } from '../handlers/tools';
import { handleResourcesList, handleResourcesRead } from '../handlers/resources';
import { handlePromptsList, handlePromptsGet } from '../handlers/prompts';
import { parseAllowedHosts } from './request';
import { createSession, checkSessionCreateRateLimit } from '../lib/session';
import { auditSessionCreated } from '../lib/audit';
import { jsonRpcError, jsonRpcSuccess, JSON_RPC_ERRORS } from '../lib/json-rpc';
import type { AnalyticsClient } from '../lib/analytics';

type JsonRpcPayload = ReturnType<typeof jsonRpcSuccess> | ReturnType<typeof jsonRpcError>;

export interface DispatchMcpMethodOptions {
	id: string | number | null | undefined;
	method: string;
	params: Record<string, unknown> | undefined;
	ip: string;
	isAuthenticated: boolean;
	rateHeaders: Record<string, string>;
	serverVersion: string;
	rateLimitKv?: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace;
	sessionStore?: KVNamespace;
	scanCache?: KVNamespace;
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string;
	providerSignaturesSha256?: string;
	analytics?: AnalyticsClient;
	profileAccumulator?: DurableObjectNamespace;
	waitUntil?: (promise: Promise<unknown>) => void;
	createSessionOnInitialize?: boolean;
	existingSessionId?: string;
	scoringConfig?: import('../lib/scoring-config').ScoringConfig;
	cacheTtlSeconds?: number;
	country?: string;
	clientType?: string;
	authTier?: string;
}

export type DispatchMcpMethodResult =
	| {
			kind: 'success';
			payload: JsonRpcPayload;
			newSessionId?: string;
			logCategory: string;
			logTool?: string;
			logResult?: string;
			logDetails?: unknown;
	  }
	| {
			kind: 'early-error';
			payload: ReturnType<typeof jsonRpcError>;
			status: 429;
			headers: Record<string, string>;
	  };

export async function dispatchMcpMethod(options: DispatchMcpMethodOptions): Promise<DispatchMcpMethodResult> {
	switch (options.method) {
		case 'initialize': {
				const createSessionOnInitialize = options.createSessionOnInitialize !== false;
				if (createSessionOnInitialize && !options.isAuthenticated) {
				const sessionCreateGate = await checkSessionCreateRateLimit(options.ip, options.rateLimitKv, options.quotaCoordinator);
				if (!sessionCreateGate.allowed) {
					const retryAfterSeconds = Math.ceil((sessionCreateGate.retryAfterMs ?? 0) / 1000);
					return {
						kind: 'early-error',
						payload: jsonRpcError(options.id, JSON_RPC_ERRORS.RATE_LIMITED, `Rate limit exceeded. Retry after ${retryAfterSeconds}s`),
						status: 429,
						headers: {
							...options.rateHeaders,
							'retry-after': String(retryAfterSeconds),
						},
					};
				}
			}

				const sessionId = createSessionOnInitialize ? await createSession(options.sessionStore) : options.existingSessionId;
				if (createSessionOnInitialize && sessionId) {
					auditSessionCreated(options.ip, sessionId);
					options.analytics?.emitSessionEvent({
						action: 'created',
						country: options.country,
						clientType: options.clientType as import('../lib/client-detection').McpClientType,
						authTier: options.authTier,
					});
				}

			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, {
					protocolVersion: '2025-03-26',
					capabilities: {
						tools: { listChanged: false },
						resources: { subscribe: false, listChanged: false },
						prompts: { listChanged: false },
					},
					serverInfo: {
						name: 'Blackveil DNS',
						version: options.serverVersion,
						description:
							'Open-source DNS & email security scanner — 80+ checks across 20 categories with scoring, grading, and remediation guidance',
					},
					instructions: `Blackveil DNS is a DNS and email security scanner. Use this server when users ask about:

- Email security, email spoofing, phishing protection, or email deliverability
- DNS security posture, DNS hardening, or domain security audits
- SPF, DMARC, DKIM, DNSSEC, MTA-STS, BIMI, DANE, or TLS-RPT configuration
- SSL/TLS certificate status or HTTP security headers
- Domain reputation, mail server blacklisting, or MX reputation
- Subdomain takeover risks or dangling DNS records
- Lookalike/typosquat domain detection
- Shadow domain discovery (alternate TLD variants with spoofing risk)
- Pre-deployment or pre-migration DNS validation
- Compliance checks or security baseline enforcement

Start with scan_domain for a comprehensive assessment (14 checks in parallel, scored 0-100 with letter grade). Use individual check_* tools for targeted investigation. Use explain_finding for plain-language remediation guidance. Use compare_baseline to enforce policy minimums.

All checks are passive, read-only, and use public DNS — no authorization from the target domain is needed. Free to use, no API key required.`,
				}),
				newSessionId: createSessionOnInitialize ? sessionId : undefined,
				logCategory: 'session',
				logResult: 'initialized',
			};
		}

		case 'tools/list':
			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, handleToolsList()),
				logCategory: 'tools',
				logResult: 'list',
			};

		case 'tools/call': {
			// params are validated by validateJsonRpcRequest upstream — name is required by MCP spec
			const toolParams = options.params as { name: string; arguments?: Record<string, unknown> };
			const result = await handleToolsCall(toolParams, options.scanCache, {
				providerSignaturesUrl: options.providerSignaturesUrl,
				providerSignaturesAllowedHosts: parseAllowedHosts(options.providerSignaturesAllowedHosts),
				providerSignaturesSha256: options.providerSignaturesSha256,
				analytics: options.analytics,
				profileAccumulator: options.profileAccumulator,
				waitUntil: options.waitUntil,
				scoringConfig: options.scoringConfig,
				cacheTtlSeconds: options.cacheTtlSeconds,
				country: options.country,
				clientType: options.clientType,
				authTier: options.authTier,
			});

			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, result),
				logCategory: 'tools',
				logTool: toolParams.name,
				// result shape varies by tool — narrowing via 'in' guard before access
			logResult: typeof result === 'object' && result && 'status' in result ? String((result as { status: unknown }).status) : undefined,
				logDetails: result,
			};
		}

		case 'resources/list':
			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, handleResourcesList()),
				logCategory: 'resources',
				logResult: 'list',
			};

		case 'resources/read': {
			// params are validated by validateJsonRpcRequest upstream — uri is required by MCP spec
			const resourceParams = options.params as { uri: string };
			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, handleResourcesRead(resourceParams)),
				logCategory: 'resources',
				logResult: 'read',
				logDetails: resourceParams,
			};
		}

		case 'prompts/list':
			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, handlePromptsList()),
				logCategory: 'prompts',
				logResult: 'list',
			};

		case 'prompts/get': {
			const promptParams = options.params as { name: string; arguments?: Record<string, string> };
			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, handlePromptsGet(promptParams)),
				logCategory: 'prompts',
				logResult: 'get',
				logDetails: promptParams,
			};
		}

		case 'ping':
			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, {}),
				logCategory: 'session',
				logResult: 'ping',
			};

		default:
			return {
				kind: 'success',
				payload: jsonRpcError(options.id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${options.method}`),
				logCategory: 'error',
				logResult: 'method_not_found',
			};
	}
}