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
