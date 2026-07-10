// SPDX-License-Identifier: BUSL-1.1

/**
 * @blackveil/dns-checks
 *
 * DNS and email security check implementations.
 * BUSL-1.1 Licensed — Copyright (c) 2023-2026 BLACKVEIL Security
 *
 * @module @blackveil/dns-checks
 */

// Types
export type {
	DNSQueryFunction,
	RawDNSQueryFunction,
	RawDNSResponse,
	FetchFunction,
	CheckResult,
	CheckCategory,
	Finding,
	Severity,
	FindingConfidence,
	CategoryTier,
	ScanScore,
} from './types';
export { SEVERITY_PENALTIES, CATEGORY_TIERS, CATEGORY_DISPLAY_WEIGHTS } from './types';

// Check utilities
export {
	createFinding,
	buildCheckResult,
	computeCategoryScore,
	inferFindingConfidence,
	sanitizeDnsData,
} from './check-utils';

// Robot policy
export { SCANNER_USER_AGENT, RobotsDisallowedError, withRobotsGate } from './robots-gate';

// Check implementations
export {
	checkSPF,
	checkDMARC,
	checkDKIM,
	checkDNSSEC,
	checkSSL,
	checkMTASTS,
	checkMX,
	checkCAA,
	checkBIMI,
	checkNS,
	checkTLSRPT,
	checkDANE,
	checkDANEHTTPS,
	checkSVCBHTTPS,
	checkSubdomainTakeover,
	checkSubdomailing,
	checkHTTPSecurity,
	// Analysis utilities
	parseDmarcTags,
	parseDnskeyAlgorithm,
	parseDsRecord,
	parseDnssecAlgorithmToken,
	parseTlsaRecord,
	parseCaaRecord,
	analyzeSecurityHeaders,
} from './checks';
export type { CaaRecord, TlsaRecord } from './checks';

// Scoring classifiers
export { classifyDmarc, appendDmarcCleanInfo } from './scoring/classifiers/dmarc';
export type { DmarcFacts } from './scoring/classifiers/dmarc';

// Cross-repo scoring parity corpus (shared contract; both repos assert their full
// check matches these). See bv-web docs/superpowers/specs/2026-05-31-cross-repo-scoring-parity-gate-design.md
export {
	DMARC_PARITY_FIXTURES,
	DANE_HTTPS_PARITY_FIXTURES,
	DANE_EMAIL_PARITY_FIXTURES,
	SVCB_HTTPS_PARITY_FIXTURES,
	DNSSEC_PARITY_FIXTURES,
	CAA_PARITY_FIXTURES,
	MX_PARITY_FIXTURES,
	TLS_RPT_PARITY_FIXTURES,
	SPF_PARITY_FIXTURES,
	DKIM_PARITY_FIXTURES,
	BIMI_PARITY_FIXTURES,
	MTA_STS_PARITY_FIXTURES,
	PARITY_CORPUS_VERSION,
} from './parity-fixtures';
export type {
	DmarcParityFixture,
	DaneHttpsParityFixture,
	DaneEmailParityFixture,
	SvcbParityFixture,
	DnssecParityFixture,
	CaaParityFixture,
	MxParityFixture,
	TlsRptParityFixture,
	SpfParityFixture,
	DkimParityFixture,
	BimiParityFixture,
	MtaStsParityFixture,
} from './parity-fixtures';

// Zod schemas
export {
	CheckCategorySchema,
	SeveritySchema,
	FindingConfidenceSchema,
	CategoryTierSchema,
	FindingSchema,
	CheckResultSchema,
	ScanScoreSchema,
} from './schemas/scoring';
