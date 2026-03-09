export {
	DnsQueryError,
	type DohResponse,
	type DnsAnswer,
	type DnsAuthority,
	type QueryDnsOptions,
	queryDns,
	type RecordTypeName,
	RecordType,
	queryCaaRecords,
	queryDnsRecords,
	queryMxRecords,
	queryTxtRecords,
	type CaaRecord,
	parseCaaRecord,
} from './lib/dns';

export {
	CATEGORY_DISPLAY_WEIGHTS,
	SEVERITY_PENALTIES,
	buildCheckResult,
	computeCategoryScore,
	computeScanScore,
	createFinding,
	inferFindingConfidence,
	scoreToGrade,
	type CheckCategory,
	type CheckResult,
	type Finding,
	type FindingConfidence,
	type ScanScore,
	type Severity,
} from './lib/scoring';

export { sanitizeDomain, sanitizeInput, validateDomain } from './lib/sanitize';

export { checkBimi } from './tools/check-bimi';
export { checkCaa } from './tools/check-caa';
export { checkDkim } from './tools/check-dkim';
export { checkDmarc, parseDmarcTags } from './tools/check-dmarc';
export { checkDnssec } from './tools/check-dnssec';
export { checkLookalikes } from './tools/check-lookalikes';
export { checkMtaSts } from './tools/check-mta-sts';
export { checkMx, type CheckMxOptions } from './tools/check-mx';
export { checkNs } from './tools/check-ns';
export { checkSpf } from './tools/check-spf';
export { checkSsl } from './tools/check-ssl';
export { checkSubdomainTakeover } from './tools/check-subdomain-takeover';
export { checkTlsrpt } from './tools/check-tlsrpt';
export { explainFinding, formatExplanation, resolveImpactNarrative, type ExplanationResult } from './tools/explain-finding';
export { formatScanReport, scanDomain, type MaturityStage, type ScanDomainResult, type ScanRuntimeOptions } from './tools/scan-domain';