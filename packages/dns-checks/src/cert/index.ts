// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate intelligence — additive, non-scoring certificate metadata.
 *
 * NOT part of the scored check matrix. Nothing here emits a `Finding` or influences
 * `computeProfileAwareScanScore`; consumers attach the result to
 * `CheckResult.metadata`. See `enrich.ts` for the sourcing caveat (CT logs describe
 * what a CA published, not what a server is currently serving).
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

export type { CertMetadata } from './cert-metadata';
export { normalizeCertDate, mergeCertSources } from './cert-metadata';

export type { ExpiryBand, ExpiryAssessment } from './expiry';
export { assessExpiry } from './expiry';

export type { ValidityWindowBand, ValidityWindowAssessment } from './validity-window';
export { assessValidityWindow, SC081_MAX_LIFETIME_DAYS, SC081_EFFECTIVE_SECONDS } from './validity-window';

export type { KeyStrengthBand } from './key-strength';
export { assessKeyStrength, normalizeKeyType, ecCurveToBits } from './key-strength';

export { CERTSPOTTER_ISSUANCES_URL, buildCertMetadataUrl, parseCertMetadataFromCt, parseCertDerFromCt } from './ct-source';

export type { DerKeyParser, CertEnrichmentResult, CertEnrichmentOptions } from './enrich';
export { enrichCertificateIntelligence } from './enrich';
