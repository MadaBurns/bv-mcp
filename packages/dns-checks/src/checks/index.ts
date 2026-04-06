// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS check implementations barrel export.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
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
export { checkHTTPSecurity } from './check-http-security';

// ── Analysis utilities (re-exported for consumers) ───────────────────────────
export { parseDmarcTags } from './dmarc-utils';
export { parseDnskeyAlgorithm, parseDsRecord } from './dnssec-analysis';
export { parseTlsaRecord } from './dane-analysis';
export type { CaaRecord } from './caa-analysis';
export { parseCaaRecord } from './caa-analysis';
export type { TlsaRecord } from './dane-analysis';
export { analyzeSecurityHeaders } from './http-security-analysis';
