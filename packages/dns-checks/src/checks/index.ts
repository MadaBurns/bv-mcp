// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS check implementations barrel export.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

// ── Check implementations ────────────────────────────────────────────────────
export { checkSPF } from './check-spf';
export { checkDMARC } from './check-dmarc';
export { checkDKIM } from './check-dkim';
export { checkDNSSEC } from './check-dnssec';
export { checkSSL } from './check-ssl';
export { checkMTASTS } from './check-mta-sts';
export { checkMX } from './check-mx';
export { checkCAA } from './check-caa';
export { checkBIMI } from './check-bimi';
export { checkNS } from './check-ns';
export { checkTLSRPT } from './check-tlsrpt';
export { checkDANE } from './check-dane';
export { checkDANEHTTPS } from './check-dane-https';
export { checkSVCBHTTPS } from './check-svcb-https';
export { checkSubdomainTakeover } from './check-subdomain-takeover';
export { checkSubdomailing } from './check-subdomailing';
export { checkHTTPSecurity, MAX_REDIRECT_HOPS as HTTP_SECURITY_MAX_REDIRECT_HOPS } from './check-http-security';
export { checkCspQuality, CSP_QUALITY_MAX_FINDINGS } from './check-csp-quality';
export type { CheckCspQualityOptions } from './check-csp-quality';

// ── Analysis utilities (re-exported for consumers) ───────────────────────────
export { parseDmarcTags } from './dmarc-utils';
export { parseDnskeyAlgorithm, parseDsRecord, parseDnssecAlgorithmToken } from './dnssec-analysis';
export {
	parseTlsaRecord,
	verifyTlsaAssociations,
	DANE_PIN_NOT_ASSESSED_REASONS,
	DANE_PIN_TRANSIENT_REASONS,
	isTransientDanePinReason,
} from './dane-analysis';
export type { CaaRecord } from './caa-analysis';
export { parseCaaRecord } from './caa-analysis';
export type {
	TlsaRecord,
	ServedCertificate,
	ServedCertificateChainEntry,
	CertificateProbeOutcome,
	TlsaVerificationContext,
	TlsaVerification,
} from './dane-analysis';
export type { CheckDaneHttpsOptions } from './check-dane-https';
export { analyzeSecurityHeaders } from './http-security-analysis';
export { estimateTxtRrsetBytes } from './spf-analysis';

// ── Shared helpers for the non-scoring web checks ────────────────────────────
export { fetchPageCapped } from './page-fetch';
export type { CappedPage, PageFetchOptions } from './page-fetch';
export { extractHtmlRefs } from './html-refs';
export type { HtmlRef, HtmlRefs } from './html-refs';

// ── CSP evaluator (pure; backs csp_quality) ──────────────────────────────────
export { parseCsp, evaluateCsp } from './csp-evaluator';
export type { CspIssue, CspRule, CspDelivery, EvaluateCspOptions } from './csp-evaluator';
