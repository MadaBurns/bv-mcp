// SPDX-License-Identifier: BUSL-1.1
/**
 * @blackveil/dns-checks/whois
 *
 * WHOIS response parsing primitives. Runtime-agnostic (no I/O).
 */

export {
	parseWhoisResponse,
	parseIanaReferral,
	MAX_RESPONSE_BYTES,
	type WhoisParseResult,
} from './parse';
