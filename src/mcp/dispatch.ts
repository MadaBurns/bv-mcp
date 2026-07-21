// SPDX-License-Identifier: BUSL-1.1

import { handleToolsList, handleToolsCall } from '../handlers/tools';
import { handleResourcesList, handleResourcesRead } from '../handlers/resources';
import { handlePromptsList, handlePromptsGet } from '../handlers/prompts';
import { parseAllowedHosts } from './request';
import { createSession, checkSessionCreateRateLimit } from '../lib/session';
import { auditSessionCreated } from '../lib/audit';
import { jsonRpcError, jsonRpcSuccess, JSON_RPC_ERRORS } from '../lib/json-rpc';
import { SERVER_INSTRUCTIONS } from './server-instructions';
import type { AnalyticsClient } from '../lib/analytics';

type JsonRpcPayload = ReturnType<typeof jsonRpcSuccess> | ReturnType<typeof jsonRpcError>;

/**
 * MCP protocol versions this server supports, newest first.
 * `2025-06-18` introduced `structuredContent` / `outputSchema`, both of which bv-mcp ships,
 * so it is the latest advertised version. `2025-03-26` is retained for backward compatibility.
 */
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26'] as const;

/** The newest protocol version this server supports — returned when the client's request can't be honored. */
export const LATEST_PROTOCOL_VERSION = '2025-06-18';

/**
 * Negotiate the MCP protocol version for an `initialize` response.
 * Per spec: echo the client's requested version when supported; otherwise return the server's latest.
 *
 * @param requested - The client's `params.protocolVersion` (untyped — may be absent or malformed).
 * @returns A supported protocol-version string.
 */
export function negotiateProtocolVersion(requested: unknown): string {
	return typeof requested === 'string' && (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
		? requested
		: LATEST_PROTOCOL_VERSION;
}

/** Classification of the incoming `MCP-Protocol-Version` HTTP header on a post-init request. */
export type ProtocolVersionHeaderState = 'absent' | 'supported' | 'unsupported';

/**
 * Classify the `MCP-Protocol-Version` request header. The transport layer accepts
 * an absent header for backward compatibility and rejects unsupported values with
 * HTTP 400, as required by MCP Streamable HTTP.
 *
 * `absent` covers a missing, empty, whitespace-only, or non-string header. The
 * value is trimmed before matching so stray header whitespace doesn't misclassify
 * an otherwise-supported version.
 */
export function classifyProtocolVersionHeader(header: string | undefined | null): ProtocolVersionHeaderState {
	if (typeof header !== 'string') return 'absent';
	const trimmed = header.trim();
	if (trimmed === '') return 'absent';
	return (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(trimmed) ? 'supported' : 'unsupported';
}

/**
 * The MCP protocol version that introduced the standard `structuredContent` channel
 * (alongside `outputSchema`). A client negotiating this version or later can read the
 * machine-readable result directly and no longer needs the legacy
 * `<!-- STRUCTURED_RESULT … -->` comment that `buildToolContent` appends in `full` format.
 */
const STRUCTURED_CONTENT_MIN_VERSION = '2025-06-18';

/**
 * Client types known to parse the embedded `<!-- STRUCTURED_RESULT … -->` comment instead of
 * the MCP-standard `structuredContent` field. The comment is preserved for these regardless of
 * protocol version. `blackveil_dns_action` (its `scan.mjs`) regex-extracts the comment for
 * `score`/`grade`/`categoryScores` and does not read `structuredContent`; it also negotiates
 * `2025-03-26`, so it would be protected by the version gate anyway — the allowlist is
 * belt-and-suspenders against a future protocol bump on that client.
 */
export const STRUCTURED_COMMENT_LEGACY_CLIENTS: ReadonlySet<string> = new Set(['blackveil_dns_action']);

/**
 * Client types verified to NOT consume the embedded comment, for which it is dropped regardless of
 * the negotiated protocol version (a positive-drop allowlist). `bv_claude_dns_proxy` is a stdio
 * bridge that forwards the human-readable `content` to Claude Desktop (an interactive LLM reading
 * prose) and never parses the comment nor reads `structuredContent`; it also negotiates `2025-03-26`,
 * so a protocol-only gate would never drop for it. Verified against the proxy source (`src/server.ts`).
 */
export const STRUCTURED_COMMENT_DROP_CLIENTS: ReadonlySet<string> = new Set(['bv_claude_dns_proxy']);

/**
 * Whether a client supports the MCP-standard `structuredContent` channel, judged from its
 * per-request `MCP-Protocol-Version` header: `true` only for a *known* supported version
 * `>= 2025-06-18`. Conservative by design — an absent, empty, unknown, older, or future header
 * → `false` (keep the legacy comment). Most clients omit the header, so this rarely fires;
 * the `clientType` allowlist is the load-bearing discriminator.
 */
export function clientSupportsStructuredContent(protocolVersionHeader: string | undefined | null): boolean {
	if (typeof protocolVersionHeader !== 'string') return false;
	const trimmed = protocolVersionHeader.trim();
	if (!(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(trimmed)) return false;
	return trimmed >= STRUCTURED_CONTENT_MIN_VERSION; // lexicographic compare is valid for YYYY-MM-DD
}

/**
 * Drop the redundant backward-compat `<!-- STRUCTURED_RESULT … -->` content item when the client
 * can read the MCP-standard `structuredContent` field instead — the "Both (conservative)" gate.
 * Strips ONLY when all hold: (1) `structuredContent` is present (so dropping the comment loses no
 * data), (2) the client is not a known comment-parser ({@link STRUCTURED_COMMENT_LEGACY_CLIENTS}),
 * and (3) it negotiated protocol `>= 2025-06-18` ({@link clientSupportsStructuredContent}) OR is a
 * verified positive-drop client ({@link STRUCTURED_COMMENT_DROP_CLIENTS}, e.g. `bv_claude_dns_proxy`).
 *
 * Pure and fail-soft: returns the input unchanged (same reference) when any condition fails or
 * nothing matches. This is the deliberate counterpart to `buildToolContent`'s `format === 'full'`
 * emission — emission stays format-driven; whether a given client *needs* it is decided here at the
 * dispatch boundary where the client/protocol signals live.
 */
export function stripRedundantStructuredComment<
	T extends { content?: Array<{ type: string; text: string }>; structuredContent?: unknown },
>(result: T, ctx: { clientType?: string; protocolVersionHeader?: string | null }): T {
	if (!result || typeof result !== 'object' || result.structuredContent === undefined) return result;
	if (ctx.clientType && STRUCTURED_COMMENT_LEGACY_CLIENTS.has(ctx.clientType)) return result;
	// A client is comment-redundant if it negotiated >= 2025-06-18 OR is a verified positive-drop client.
	const redundant = clientSupportsStructuredContent(ctx.protocolVersionHeader) || (ctx.clientType ? STRUCTURED_COMMENT_DROP_CLIENTS.has(ctx.clientType) : false);
	if (!redundant) return result;
	const content = result.content;
	if (!Array.isArray(content)) return result;
	const filtered = content.filter((c) => !(c?.type === 'text' && typeof c.text === 'string' && c.text.trimStart().startsWith('<!-- STRUCTURED_RESULT')));
	return filtered.length === content.length ? result : { ...result, content: filtered };
}

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
	/** ProfileAccumulator write-sharding mode (R10, default-off). Threaded to ToolRuntimeOptions. */
	profileAccumulatorShardMode?: import('../lib/profile-accumulator').AccumulatorShardMode;
	waitUntil?: (promise: Promise<unknown>) => void;
	createSessionOnInitialize?: boolean;
	existingSessionId?: string;
	scoringConfig?: import('@blackveil/dns-checks/scoring').ScoringConfig;
	cacheTtlSeconds?: number;
	scanTimeoutMs?: number;
	perCheckTimeoutMs?: number;
	/** Custom secondary DoH endpoint URL (bv-dns). */
	secondaryDohEndpoint?: string;
	/** Auth token for custom secondary DoH. */
	secondaryDohToken?: string;
	country?: string;
	clientType?: string;
	/** Raw `MCP-Protocol-Version` request header — used to drop the redundant STRUCTURED_RESULT comment for structuredContent-capable clients. */
	protocolVersionHeader?: string;
	authTier?: string;
	keyHash?: string;
	/** Cloudflare edge colo (`request.cf.colo`) for per-datacenter tool_call analytics grouping. Threaded to handleToolsCall. */
	colo?: string;
	/** Geo enrichment (request.cf) for the tool_call AE geo blobs. Threaded to handleToolsCall. */
	region?: string;
	city?: string;
	asn?: number;
	/**
	 * MCP session ID from the `mcp-session-id` request header. Threaded to
	 * handleToolsCall so readAndUpdateLastTool can resolve the priorTool
	 * dimension (blob12) from in-memory session state. Optional — absent on
	 * sessionless paths → priorTool='unknown'.
	 */
	sessionId?: string;
	certstream?: { fetch: typeof fetch };
	certstreamAuthToken?: string;
	whoisBinding?: { fetch: typeof fetch };
	/** Operator-only bv-recon service binding. Fail-soft; absent on BSL self-hosts. */
	reconBinding?: { fetch: typeof fetch };
	/** Bearer admin token forwarded to bv-recon. */
	reconAuthToken?: string;
	/** Operator-only bv-tls-probe service binding (negotiated-TLS-version detection). Fail-soft; absent on BSL self-hosts. */
	tlsProbeBinding?: { fetch: typeof fetch };
	/** Bearer token forwarded to bv-tls-probe. */
	tlsProbeAuthToken?: string;
	/** Service binding to bv-web's internal M365 proxy surface. Fail-soft; absent when bv-web is not provisioned. */
	m365Proxy?: { fetch: typeof fetch };
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to bv-web's internal M365 endpoints. */
	m365ProxyAuthToken?: string;
	/** Service binding to bv-web (BV_WEB) used by get_domain_rank to call the C1 benchmark endpoint. Fail-soft; absent on BSL self-hosts. */
	bvWebBenchmark?: { fetch: typeof fetch };
	/** Bearer token (BV_WEB_INTERNAL_KEY) forwarded to the C1 benchmark endpoint. */
	bvWebBenchmarkAuthToken?: string;
	infraProbe?: { fetch: typeof fetch };
	brandAuditDb?: D1Database;
	brandAuditQueue?: { send(message: unknown, options?: { contentType?: 'json' }): Promise<void> };
	brandReportsR2?: R2Bucket;
	/** Public origin of the inbound request — brand_audit_get_report builds the /reports/ PDF download URL from it. */
	publicOrigin?: string;
	browserRenderer?: { fetch: typeof fetch };
	principalId?: string;
	/** T13 — runtime-default for `discover_brand_domains` discovery_mode. */
	discoveryModeDefault?: string;
	/** Tier 0/1/2 lookup closures wrapping the private brand-discovery service bindings. Undefined on BSL self-hosts. */
	tier0Lookup?: (domain: string) => Promise<import('../lib/brand-tier0-enterprise').Tier0Result>;
	tier1Lookup?: (domain: string) => Promise<import('../lib/brand-tier1-graph').Tier1Result>;
	tier2Lookup?: (domain: string) => Promise<import('../lib/brand-tier2-evidence').Tier2Result>;
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
			status: 200 | 429;
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

				// Do NOT delete the old session on re-initialize — mcp-remote
				// reconnects the notification stream periodically, and deleting
				// the old session creates a race where in-flight tools/call
				// requests with the old session ID get a 404. Old sessions
				// expire naturally via TTL (2 hours) and are cleaned up by
				// periodic in-memory pruning + KV expirationTtl.
				const sessionId = createSessionOnInitialize ? await createSession(options.sessionStore, options.analytics, options.waitUntil) : options.existingSessionId;
				if (createSessionOnInitialize && sessionId) {
					auditSessionCreated(options.ip, sessionId);
					// The client's DECLARED identity from the initialize handshake —
					// the attribution key for the unknown-UA connector surge. Read
					// defensively (client-controlled, optional per MCP spec) and used
					// for analytics only, never auth/tier.
					const clientInfo = options.params?.clientInfo as { name?: unknown } | undefined;
					const declaredClient = typeof clientInfo?.name === 'string' ? clientInfo.name : undefined;
					options.analytics?.emitSessionEvent({
						action: 'created',
						country: options.country,
						clientType: options.clientType as import('../lib/client-detection').McpClientType,
						authTier: options.authTier,
						keyHash: options.keyHash,
						declaredClient,
					});
				}

			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, {
					protocolVersion: negotiateProtocolVersion(options.params?.protocolVersion),
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
					instructions: SERVER_INSTRUCTIONS,
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
				// Wire the binding-degradation analytics sink ONCE here (R1): when an
				// analytics client is present, recon/tls-probe wrappers emit the
				// `degradation` event on a PRESENT-binding failure so the cron alert
				// can fire. Undefined when analytics is unavailable. Fail-open.
				onBindingDegradation: options.analytics ? (e) => options.analytics?.emitDegradationEvent(e) : undefined,
				profileAccumulator: options.profileAccumulator,
				profileAccumulatorShardMode: options.profileAccumulatorShardMode,
				waitUntil: options.waitUntil,
				scoringConfig: options.scoringConfig,
				cacheTtlSeconds: options.cacheTtlSeconds,
				scanTimeoutMs: options.scanTimeoutMs,
				perCheckTimeoutMs: options.perCheckTimeoutMs,
				secondaryDoh: options.secondaryDohEndpoint
					? { endpoint: options.secondaryDohEndpoint, token: options.secondaryDohToken }
					: undefined,
				country: options.country,
				clientType: options.clientType,
				authTier: options.authTier,
				keyHash: options.keyHash,
				colo: options.colo,
				region: options.region,
				city: options.city,
				asn: options.asn,
				sessionId: options.sessionId,
				certstream: options.certstream,
				certstreamAuthToken: options.certstreamAuthToken,
				whoisBinding: options.whoisBinding,
				reconBinding: options.reconBinding,
				reconAuthToken: options.reconAuthToken,
				tlsProbeBinding: options.tlsProbeBinding,
				tlsProbeAuthToken: options.tlsProbeAuthToken,
				m365Proxy: options.m365Proxy,
				m365ProxyAuthToken: options.m365ProxyAuthToken,
				bvWebBenchmark: options.bvWebBenchmark,
				bvWebBenchmarkAuthToken: options.bvWebBenchmarkAuthToken,
				infraProbe: options.infraProbe,
				brandAuditDb: options.brandAuditDb,
				brandAuditQueue: options.brandAuditQueue,
				brandReportsR2: options.brandReportsR2,
				publicOrigin: options.publicOrigin,
				browserRenderer: options.browserRenderer,
				discoveryModeDefault: options.discoveryModeDefault,
				principalId: options.principalId,
				rateLimitKv: options.rateLimitKv,
				tier0Lookup: options.tier0Lookup,
				tier1Lookup: options.tier1Lookup,
				tier2Lookup: options.tier2Lookup,
			});

			// Drop the redundant backward-compat STRUCTURED_RESULT comment for clients that read
			// the MCP-standard structuredContent field (conservative — keeps it for legacy
			// comment-parsers and pre-2025-06-18 / header-less clients). See buildToolContent.
			const finalResult = stripRedundantStructuredComment(result, {
				clientType: options.clientType,
				protocolVersionHeader: options.protocolVersionHeader,
			});

			return {
				kind: 'success',
				payload: jsonRpcSuccess(options.id, finalResult),
				logCategory: 'tools',
				logTool: toolParams.name,
				// result shape varies by tool — narrowing via 'in' guard before access
			logResult: typeof finalResult === 'object' && finalResult && 'status' in finalResult ? String((finalResult as { status: unknown }).status) : undefined,
				logDetails: finalResult,
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
				payload: jsonRpcError(options.id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, 'Method not found'),
				logCategory: 'error',
				logResult: 'method_not_found',
			};
	}
}
