// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-discovery primitives (Phase-4 of the customer-domain expansion roadmap).
 */

export { correlateSans } from './san-correlator';
export type { SanCorrelationOptions, SanCorrelationResult } from './san-correlator';

export { correlateNs } from './ns-correlator';
export type {
	NsCorrelationOptions,
	NsCorrelationResult,
	NsCoOwnedCandidate,
	DnsQueryFn as NsDnsQueryFn,
} from './ns-correlator';

export { mineDmarcRua } from './dmarc-rua-miner';
export type {
	DmarcRuaOptions,
	DmarcRuaResult,
	DmarcRuaDomain,
	RuaClassification,
} from './dmarc-rua-miner';

export { detectDkimKeyReuse } from './dkim-key-reuse';
export type {
	DkimKeyReuseOptions,
	DkimKeyReuseResult,
	DkimCoOwnedCandidate,
} from './dkim-key-reuse';
