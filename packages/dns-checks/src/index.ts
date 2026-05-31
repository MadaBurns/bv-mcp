/**
 * @blackveil/dns-checks
 *
 * DNS and email security check implementations.
 * BSL 1.1 Licensed — Copyright (c) 2023-2026 BlackVeil Security Ltd.
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
	SVCB_HTTPS_PARITY_FIXTURES,
	DNSSEC_PARITY_FIXTURES,
	PARITY_CORPUS_VERSION,
} from './parity-fixtures';
export type {
	DmarcParityFixture,
	DaneHttpsParityFixture,
	SvcbParityFixture,
	DnssecParityFixture,
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
