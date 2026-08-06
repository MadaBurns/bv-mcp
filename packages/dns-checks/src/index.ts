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
	ZoneDelegationStatus,
	ZoneContext,
} from './types';
export { SEVERITY_PENALTIES, CATEGORY_TIERS, CATEGORY_DISPLAY_WEIGHTS } from './types';

// The nullable-`ScanScore` narrowing guard. Exported from the PACKAGE ROOT as well
// as from `./scoring`: the breaking change (`overall`/`grade` became nullable) is
// visible to anyone importing `ScanScore` from here, so its remedy must be
// reachable from the same entrypoint — otherwise a consumer meets the break at one
// specifier and has to discover the fix at another.
export { isGraded } from './scoring/engine';

// Check utilities
export { createFinding, buildCheckResult, computeCategoryScore, inferFindingConfidence, sanitizeDnsData } from './check-utils';

// Robot policy
export { SCANNER_USER_AGENT, RobotsDisallowedError, withRobotsGate } from './robots-gate';

// DKIM selector probe list. Exported so downstream consumers can assert provider
// coverage without re-declaring the list (a second copy would drift and, because
// a probe miss hard-floors the dkim category at 50, drift is scored as a real
// finding on a domain whose email auth is fine).
export { COMMON_DKIM_SELECTORS } from './checks/dkim-selectors';

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

// Certificate intelligence — ADDITIVE, NON-SCORING metadata (issuer / expiry /
// key strength from Certificate Transparency). Emits no `Finding` and never
// influences `computeProfileAwareScanScore`: consumers attach the result to
// `CheckResult.metadata`. Also available at the `./cert` subpath.
export type {
	CertMetadata,
	ExpiryBand,
	ExpiryAssessment,
	KeyStrengthBand,
	DerKeyParser,
	CertEnrichmentResult,
	CertEnrichmentOptions,
} from './cert';
export {
	normalizeCertDate,
	mergeCertSources,
	assessExpiry,
	assessKeyStrength,
	normalizeKeyType,
	ecCurveToBits,
	CERTSPOTTER_ISSUANCES_URL,
	buildCertMetadataUrl,
	parseCertMetadataFromCt,
	parseCertDerFromCt,
	enrichCertificateIntelligence,
} from './cert';
