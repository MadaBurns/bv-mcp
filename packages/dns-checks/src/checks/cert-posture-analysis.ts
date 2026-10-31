// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate posture analysis — pure functions behind the non-scoring `cert_posture` check.
 *
 * Judges ONE injected certificate (`CertMetadata`) on three axes the cert vocabulary already
 * bands (expiry, key strength, validity window) plus one new comparison: the CA that actually
 * issued the certificate against the CAs the domain's CAA policy authorises.
 *
 * Nothing here touches the network or a clock: the certificate, the resolved CAA policy and
 * `nowSeconds` all arrive as arguments, so the package stays runtime-agnostic and every
 * band is deterministic under test.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding, Severity } from '../types';
import { createFinding } from '../check-utils';
import { assessExpiry, type ExpiryBand } from '../cert/expiry';
import { assessKeyStrength } from '../cert/key-strength';
import { assessValidityWindow } from '../cert/validity-window';
import type { CertMetadata } from '../cert/cert-metadata';
import { MAX_CAA_ISSUERS, type EffectiveCaa } from './caa-analysis';
import { parseTlsaRecord, verifyTlsaAssociations, type ServedCertificate, type TlsaRecord } from './dane-analysis';

/** CA/Browser Forum maximum certificate lifetime (398 days) in force since 2020-09-01. */
export const MAX_CERT_VALIDITY_DAYS = 398;

/** Bound on attacker-influenceable text (an issuer DN comes from a CT log entry) rendered into a finding. */
const MAX_RENDERED_TEXT = 200;

// ─── CA identification ──────────────────────────────────────────────────────

/**
 * One certificate authority, as seen from both sides of the comparison: the issuer-domain-names
 * a domain owner writes in a CAA `issue` record, and the strings that appear in the issuing
 * certificate's DN.
 *
 * HAND-SEEDED and deliberately small. There is no authoritative machine-readable mapping from a
 * CAA issuer-domain to a DN, so an issuer this table does not know is reported as NOT ASSESSED —
 * never guessed, and never a mismatch.
 */
export interface CaProfile {
	/** Stable id used in finding metadata. */
	id: string;
	/** Display name. */
	name: string;
	/** CAA `issue` issuer-domain-names that authorise this CA (lowercase). */
	caaDomains: readonly string[];
	/** Substrings of the issuer `O=` (or whole issuer string when it has no DN structure), alphanumerics only, lowercase. */
	orgNeedles: readonly string[];
	/** Patterns for the issuer `CN=`. */
	cnPatterns: readonly RegExp[];
}

/** Order matters: a profile earlier in the list wins (ZeroSSL's DN also mentions Sectigo-era strings). */
export const CA_PROFILES: readonly CaProfile[] = [
	{
		id: 'letsencrypt',
		name: "Let's Encrypt",
		caaDomains: ['letsencrypt.org'],
		orgNeedles: ['letsencrypt', 'internetsecurityresearchgroup'],
		cnPatterns: [/^(R|E)\d{1,2}$/],
	},
	{
		id: 'google-trust-services',
		name: 'Google Trust Services',
		caaDomains: ['pki.goog'],
		orgNeedles: ['googletrustservices'],
		cnPatterns: [/^(WR|WE)\d{1,2}$/, /^GTS\b/i],
	},
	{
		id: 'digicert',
		name: 'DigiCert',
		caaDomains: ['digicert.com', 'geotrust.com', 'thawte.com', 'rapidssl.com'],
		orgNeedles: ['digicert', 'geotrust', 'thawte', 'rapidssl'],
		cnPatterns: [/digicert|geotrust|thawte|rapidssl/i],
	},
	{
		id: 'zerossl',
		name: 'ZeroSSL',
		caaDomains: ['zerossl.com', 'sectigo.com', 'comodoca.com'],
		orgNeedles: ['zerossl'],
		cnPatterns: [/zerossl/i],
	},
	{
		id: 'sectigo',
		name: 'Sectigo',
		caaDomains: ['sectigo.com', 'comodoca.com', 'usertrust.com'],
		orgNeedles: ['sectigo', 'comodo', 'usertrust'],
		cnPatterns: [/sectigo|comodo/i],
	},
	{
		id: 'globalsign',
		name: 'GlobalSign',
		caaDomains: ['globalsign.com'],
		orgNeedles: ['globalsign'],
		cnPatterns: [/globalsign/i],
	},
	{
		id: 'amazon',
		name: 'Amazon Trust Services',
		caaDomains: ['amazon.com', 'amazontrust.com', 'awstrust.com', 'amazonaws.com'],
		orgNeedles: ['amazon'],
		cnPatterns: [/^Amazon\b/i],
	},
	{
		id: 'ssl-com',
		name: 'SSL.com',
		caaDomains: ['ssl.com'],
		orgNeedles: ['sslcorp', 'sslcom'],
		cnPatterns: [/ssl\.com/i],
	},
	{
		id: 'entrust',
		name: 'Entrust',
		caaDomains: ['entrust.net'],
		orgNeedles: ['entrust'],
		cnPatterns: [/entrust/i],
	},
	{
		id: 'buypass',
		name: 'Buypass',
		caaDomains: ['buypass.com'],
		orgNeedles: ['buypass'],
		cnPatterns: [/buypass/i],
	},
	{
		id: 'godaddy',
		name: 'GoDaddy / Starfield',
		caaDomains: ['godaddy.com', 'starfieldtech.com'],
		orgNeedles: ['godaddy', 'starfield'],
		cnPatterns: [/godaddy|starfield/i],
	},
];

/**
 * Pull `O=` and `CN=` out of an issuer DN. Tolerant of the comma, slash and semicolon
 * separators CT sources use. The value class is bounded, so a crafted DN cannot backtrack.
 */
export function parseIssuerDn(issuerDn: string): { org: string | null; cn: string | null } {
	let org: string | null = null;
	let cn: string | null = null;
	for (const match of issuerDn.matchAll(/(?:^|[,/;])\s*(O|CN)=([^,/;]{1,200})/gi)) {
		const value = match[2].trim().replace(/^"|"$/g, '');
		if (match[1].toUpperCase() === 'O') org ??= value;
		else cn ??= value;
	}
	return { org, cn };
}

function alnum(text: string): string {
	return text.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function profileMatches(profile: CaProfile, orgHaystack: string, cn: string | null): boolean {
	return profile.orgNeedles.some((needle) => orgHaystack.includes(needle)) || (cn !== null && profile.cnPatterns.some((p) => p.test(cn)));
}

/**
 * Map an issuer DN onto a known CA, or null when the issuer is absent or not in the table.
 * Null is "unknown", never "untrusted".
 */
export function identifyIssuingCa(issuerDn: string | null | undefined): CaProfile | null {
	if (!issuerDn) return null;
	const { org, cn } = parseIssuerDn(issuerDn);
	// No DN structure at all (a bare display name) → match the needles against the whole string.
	const orgHaystack = alnum(org ?? (cn === null ? issuerDn : ''));
	return CA_PROFILES.find((profile) => profileMatches(profile, orgHaystack, cn)) ?? null;
}

// ─── Findings ────────────────────────────────────────────────────────────────

/** Per-run context threaded through every finding builder. */
export interface PostureContext {
	source: CertMetadata['source'];
	/** Appended to every finding: what the certificate data is, and is not. */
	caveat: string;
}

/** The caveat that rides on every finding — the data is what a CA published, not necessarily what is served. */
export function buildPostureContext(source: CertMetadata['source']): PostureContext {
	return {
		source,
		caveat:
			source === 'ct'
				? 'Certificate data comes from Certificate Transparency logs (what was issued), not the certificate currently served.'
				: 'Certificate data was read from a live TLS handshake of one endpoint; other endpoints may serve a different certificate.',
	};
}

function clampText(text: string): string {
	return text.length > MAX_RENDERED_TEXT ? `${text.slice(0, MAX_RENDERED_TEXT)}...(truncated)` : text;
}

function posture(ctx: PostureContext, title: string, severity: Severity, detail: string, metadata: Record<string, unknown> = {}): Finding {
	return createFinding('cert_posture', title, severity, `${detail} ${ctx.caveat}`, {
		certSource: ctx.source,
		// A `high` finding here is a defect in a certificate that exists, not an assertion that a control is absent.
		...(severity === 'high' ? { missingControl: false } : {}),
		...metadata,
	});
}

/** An honest "we did not measure this" finding: info severity, flagged so no consumer reads it as a pass. */
function notAssessed(ctx: PostureContext, title: string, detail: string, metadata: Record<string, unknown> = {}): Finding {
	return posture(ctx, title, 'info', detail, { notAssessed: true, confidence: 'heuristic', ...metadata });
}

const EXPIRY_SEVERITY: Record<Exclude<ExpiryBand, 'unknown'>, Severity> = {
	expired: 'high',
	critical: 'high',
	warning: 'medium',
	ok: 'info',
};

const EXPIRY_TITLE: Record<Exclude<ExpiryBand, 'unknown'>, string> = {
	expired: 'Certificate has expired',
	critical: 'Certificate expires within 7 days',
	warning: 'Certificate expires within 30 days',
	ok: 'Certificate expiry is healthy',
};

function describeExpiry(band: Exclude<ExpiryBand, 'unknown'>, days: number): string {
	if (band === 'expired') return `The newest certificate expired roughly ${Math.abs(days)} day(s) ago.`;
	return `The newest certificate expires in ${days} day(s).`;
}

/** Expiry banded by `assessExpiry`: expired and within-7-days are high, within-30-days medium, otherwise info. */
export function expiryFinding(ctx: PostureContext, cert: CertMetadata, nowSeconds: number): Finding {
	const { band, daysRemaining } = assessExpiry(cert.notAfter, nowSeconds);
	if (band === 'unknown' || daysRemaining === null) {
		return notAssessed(ctx, 'Certificate expiry not assessed', 'The certificate carries no expiry date, so expiry was not assessed.', {
			expiryBand: 'unknown',
		});
	}
	return posture(ctx, EXPIRY_TITLE[band], EXPIRY_SEVERITY[band], describeExpiry(band, daysRemaining), {
		expiryBand: band,
		daysRemaining,
	});
}

function describeKey(cert: CertMetadata): string {
	const type = cert.keyType && cert.keyType !== 'unknown' ? cert.keyType.toUpperCase() : 'unknown-type';
	return cert.keyBits != null ? `${type} ${cert.keyBits}-bit` : type;
}

/**
 * Key strength banded by `assessKeyStrength`. Key material is host-injected (this package has no
 * DER parser), so an absent key is a distinct not-assessed finding, never a pass. A key type of
 * `unknown` is withheld from the banding: sized-but-untyped material would otherwise read as
 * "acceptable" with nothing to judge it against.
 */
export function keyStrengthFinding(ctx: PostureContext, cert: CertMetadata): Finding {
	const keyType = cert.keyType === 'unknown' ? undefined : cert.keyType;
	const { band, reasons } = assessKeyStrength({ keyType, keyBits: cert.keyBits, sigAlg: cert.sigAlg });
	if (band === 'unknown') {
		return notAssessed(
			ctx,
			'Certificate key strength not assessed',
			'No parsed public-key type and size were supplied with the certificate, so key strength was not assessed.',
			{ keyStrengthBand: 'unknown' },
		);
	}
	if (band === 'weak') {
		return posture(ctx, 'Certificate uses a weak key or signature', 'high', `${reasons.join('; ')}.`, {
			keyStrengthBand: band,
			keyReasons: reasons,
		});
	}
	return posture(ctx, `Certificate key strength is ${band}`, 'info', `The certificate key is ${describeKey(cert)}.`, {
		keyStrengthBand: band,
	});
}

/** Validity window over the CA/B Forum 398-day maximum is medium; a window we cannot measure is not-assessed. */
export function validityWindowFinding(ctx: PostureContext, cert: CertMetadata): Finding {
	const { days } = assessValidityWindow(cert);
	if (days === null) {
		return notAssessed(
			ctx,
			'Certificate validity window not assessed',
			'The certificate is missing its start or end date, so its validity window was not assessed.',
			{
				validityDays: null,
			},
		);
	}
	if (days > MAX_CERT_VALIDITY_DAYS) {
		return posture(
			ctx,
			`Certificate validity window exceeds ${MAX_CERT_VALIDITY_DAYS} days`,
			'medium',
			`The certificate is valid for ${days} days, longer than the ${MAX_CERT_VALIDITY_DAYS}-day maximum the CA/Browser Forum allows for publicly trusted certificates.`,
			{ validityDays: days },
		);
	}
	return posture(ctx, 'Certificate validity window is within limits', 'info', `The certificate is valid for ${days} days.`, {
		validityDays: days,
	});
}

// ─── CAA policy vs actual issuer ─────────────────────────────────────────────

export type CaaIssuerOutcome = 'inconclusive' | 'absent' | 'unrestricted' | 'no-issuance' | 'unmapped' | 'unauthorised' | 'honoured';

/** What the CAA policy says before any issuer is compared: unreadable, absent, silent on `issue`, deny-all, or a real grant list. */
function caaPolicyShape(caa: EffectiveCaa): 'inconclusive' | 'absent' | 'unrestricted' | 'no-issuance' | 'restricted' {
	if (caa.inconclusive) return 'inconclusive';
	if (caa.foundAt === null) return 'absent';
	if (!caa.hasIssueTag) return 'unrestricted';
	return caa.noIssuance ? 'no-issuance' : 'restricted';
}

/** Compare the issuing CA against a non-empty `issue` grant list. */
function compareIssuer(caa: EffectiveCaa, ca: CaProfile | null): 'unmapped' | 'honoured' | 'inconclusive' | 'unauthorised' {
	if (ca === null) return 'unmapped';
	if (ca.caaDomains.some((domain) => caa.issuers.includes(domain))) return 'honoured';
	// A clipped grant list cannot prove the CA is absent from it.
	return caa.issuersTruncated ? 'inconclusive' : 'unauthorised';
}

/** Classify the CAA policy against the CA that issued the certificate. Pure. */
export function classifyCaaIssuer(caa: EffectiveCaa, ca: CaProfile | null): CaaIssuerOutcome {
	const shape = caaPolicyShape(caa);
	return shape === 'restricted' ? compareIssuer(caa, ca) : shape;
}

function renderIssuers(caa: EffectiveCaa): string {
	const shown = caa.issuers.slice(0, MAX_CAA_ISSUERS).join(', ');
	return caa.issuers.length > MAX_CAA_ISSUERS || caa.issuersTruncated ? `${shown} (list truncated)` : shown;
}

/** Everything one CAA-vs-issuer finding builder needs. */
interface CaaFindingInput {
	ctx: PostureContext;
	caa: EffectiveCaa;
	ca: CaProfile | null;
	issuerDn: string | null;
	/** Metadata shared by every outcome. */
	base: Record<string, unknown>;
}

const NOT_ASSESSED_TITLE = 'CAA policy vs issuer not assessed';

/** One builder per outcome: the outcome picks the severity, the title and the sentence. */
const CAA_FINDING_BUILDERS: Record<CaaIssuerOutcome, (input: CaaFindingInput) => Finding> = {
	inconclusive: ({ ctx, base }) =>
		notAssessed(
			ctx,
			NOT_ASSESSED_TITLE,
			'The CAA policy could not be read completely (a lookup failed or the grant list was truncated), so the issuing CA was not compared with it.',
			base,
		),
	absent: ({ ctx, base }) =>
		posture(
			ctx,
			'CAA policy absent, nothing to compare',
			'info',
			'The domain publishes no CAA policy, so any CA may issue and there is no authorisation to compare the issuer against.',
			base,
		),
	unrestricted: ({ ctx, caa, base }) =>
		posture(
			ctx,
			'CAA policy does not restrict issuance',
			'info',
			`The CAA policy at ${caa.foundAt} carries no "issue" property, so it does not limit which CAs may issue.`,
			base,
		),
	'no-issuance': ({ ctx, caa, issuerDn, base }) =>
		posture(
			ctx,
			'Certificate logged although CAA forbids all issuance',
			'high',
			`The CAA policy at ${caa.foundAt} forbids all issuance (issue ";"), yet a certificate issued by ${clampText(issuerDn ?? 'an unknown CA')} is on record. Either the policy was added after issuance or the certificate was issued in breach of it.`,
			base,
		),
	unmapped: ({ ctx, caa, issuerDn, base }) =>
		notAssessed(
			ctx,
			NOT_ASSESSED_TITLE,
			`The issuer "${clampText(issuerDn ?? 'unknown')}" is not in this package's table of known CAs, so it was not compared with the CAA policy (allowed: ${renderIssuers(caa)}).`,
			{ ...base, rawIssuer: issuerDn === null ? null : clampText(issuerDn) },
		),
	unauthorised: ({ ctx, caa, ca, base }) =>
		posture(
			ctx,
			'Certificate issued by a CA your CAA does not authorise',
			'high',
			`The certificate was issued by ${ca?.name ?? 'a known CA'}, but the CAA policy at ${caa.foundAt} authorises only ${renderIssuers(caa)}. CAA is checked at issuance time, so the policy may have been tightened after this certificate was issued.`,
			{ ...base, allowedIssuers: caa.issuers.slice(0, MAX_CAA_ISSUERS) },
		),
	honoured: ({ ctx, caa, ca, base }) =>
		posture(
			ctx,
			'CAA honoured by the issuing CA',
			'info',
			`The certificate was issued by ${ca?.name ?? 'a known CA'}, which the CAA policy at ${caa.foundAt} authorises.`,
			base,
		),
};

/**
 * CAA-allowed CAs vs the CA that actually issued the certificate.
 *
 * Outcomes: issuer in the allowed set → info "honoured"; a KNOWN CA outside the set → high; an
 * issuer this package cannot map → not-assessed naming the raw issuer; no CAA → info; `issue ";"`
 * with a certificate on record → high. CAA is evaluated at issuance time, so a mismatch can also
 * mean the policy was tightened after issuance — the high finding says so.
 */
export function caaIssuerFinding(ctx: PostureContext, caa: EffectiveCaa, issuerDn: string | null): Finding {
	const ca = identifyIssuingCa(issuerDn);
	const outcome = classifyCaaIssuer(caa, ca);
	const base = { caaOutcome: outcome, caaFoundAt: caa.foundAt, issuingCa: ca?.id ?? null };
	return CAA_FINDING_BUILDERS[outcome]({ ctx, caa, ca, issuerDn, base });
}

// ─── DANE (TLSA) vs logged certificates ──────────────────────────────────────

/** What a TLSA lookup at one owner name returned. `unreadable` = no answer was obtained (throw/SERVFAIL/REFUSED). */
export interface TlsaLookup {
	/** The TLSA owner name, e.g. `_443._tcp.example.com`. */
	name: string;
	records: string[];
	unreadable: boolean;
}

type DaneRecordVerdict = 'matched' | 'unmatched' | 'unverifiable';

const DANE_TITLE = 'DANE vs logged certificate';

/** The comparison data is CT-derived and host-injected, so a miss never proves a broken pin. */
const DANE_CONTEXT: PostureContext = {
	source: 'ct',
	caveat: `${buildPostureContext('ct').caveat} The certificate actually served may be private or not logged, so check the live endpoint before treating a mismatch as a fault.`,
};

/** DANE-TA / PKIX-TA pin an issuing CA, which a lone leaf certificate cannot refute. */
function isTrustAnchorUsage(record: TlsaRecord): boolean {
	return record.usage === 0 || record.usage === 2;
}

function hasIssuerChain(cert: ServedCertificate): boolean {
	return (cert.chain?.length ?? 0) > 1;
}

function verdictAgainstCert(record: TlsaRecord, cert: ServedCertificate): DaneRecordVerdict {
	const verification = verifyTlsaAssociations([record], cert);
	if (verification.matched.length > 0) return 'matched';
	if (verification.unverifiable.length > 0) return 'unverifiable';
	// A trust-anchor record that does not match a leaf-only certificate may still match the issuer we were not given.
	return isTrustAnchorUsage(record) && !hasIssuerChain(cert) ? 'unverifiable' : 'unmatched';
}

/** One logged certificate matching is enough (RFC 7671: any matching association validates); one uncomparable withholds the verdict. */
function verdictAcrossCerts(record: TlsaRecord, certs: readonly ServedCertificate[]): DaneRecordVerdict {
	const verdicts = certs.map((cert) => verdictAgainstCert(record, cert));
	if (verdicts.includes('matched')) return 'matched';
	return verdicts.includes('unverifiable') ? 'unverifiable' : 'unmatched';
}

function unreadableTlsaFinding(lookup: TlsaLookup): Finding {
	return notAssessed(
		DANE_CONTEXT,
		`${DANE_TITLE} not assessed`,
		`The TLSA lookup at ${lookup.name} failed before any resolver answered, so DANE was not compared with the logged certificates.`,
		{ daneOutcome: 'lookup-failed', tlsaName: lookup.name },
	);
}

function noTlsaFinding(lookups: readonly TlsaLookup[]): Finding {
	return posture(
		DANE_CONTEXT,
		`${DANE_TITLE}: no TLSA record, nothing to compare`,
		'info',
		`No TLSA record was found at ${lookups.map((l) => l.name).join(' or ')}, so there is no DANE pin to compare with a logged certificate.`,
		{ daneOutcome: 'no-tlsa' },
	);
}

/** Judge one TLSA RRset that is present against the supplied logged certificates. */
function tlsaPresentFinding(lookup: TlsaLookup, certs: readonly ServedCertificate[]): Finding {
	const base = { tlsaName: lookup.name, tlsaRecordCount: lookup.records.length, loggedCertificateCount: certs.length };
	if (certs.length === 0) {
		return notAssessed(
			DANE_CONTEXT,
			`${DANE_TITLE} not assessed`,
			`A TLSA record is published at ${lookup.name}, but no logged certificate was supplied to compare it with.`,
			{ ...base, daneOutcome: 'no-certificate-supplied' },
		);
	}
	const records = lookup.records.map(parseTlsaRecord).filter((record): record is TlsaRecord => record !== null);
	const verdicts = records.map((record) => verdictAcrossCerts(record, certs));
	if (verdicts.includes('matched')) {
		return posture(
			DANE_CONTEXT,
			`${DANE_TITLE}: TLSA matches a logged certificate`,
			'info',
			`A TLSA record at ${lookup.name} matches one of ${certs.length} logged certificate(s).`,
			{ ...base, daneOutcome: 'matched' },
		);
	}
	if (verdicts.length === 0 || verdicts.includes('unverifiable')) {
		return notAssessed(
			DANE_CONTEXT,
			`${DANE_TITLE} not assessed`,
			`The TLSA record(s) at ${lookup.name} could not be compared with the logged certificates (unparseable record, unsupported field, or a trust-anchor record with only a leaf certificate available).`,
			{ ...base, daneOutcome: 'not-comparable' },
		);
	}
	return posture(
		DANE_CONTEXT,
		`${DANE_TITLE}: TLSA matches no logged certificate`,
		'medium',
		`The TLSA record(s) at ${lookup.name} match none of ${certs.length} logged certificate(s).`,
		{ ...base, daneOutcome: 'mismatch' },
	);
}

/**
 * DANE TLSA records against host-injected, CT-derived certificates. Pure.
 *
 * Outcomes per owner name: a record matches a logged certificate → info; TLSA present but
 * nothing matches → medium (with the "may be private / not in CT" caveat); TLSA present with no
 * certificate supplied, an unparseable/unsupported record, or a trust-anchor record against a
 * leaf-only certificate → not-assessed; no TLSA anywhere → one info "nothing to compare".
 * An unanswered lookup is not-assessed and suppresses the "no TLSA" claim.
 */
export function daneVsLoggedCertFindings(lookups: readonly TlsaLookup[], certs: readonly ServedCertificate[]): Finding[] {
	const unreadable = lookups.filter((lookup) => lookup.unreadable).map(unreadableTlsaFinding);
	const present = lookups.filter((lookup) => lookup.records.length > 0).map((lookup) => tlsaPresentFinding(lookup, certs));
	const findings = [...unreadable, ...present];
	return findings.length > 0 ? findings : [noTlsaFinding(lookups)];
}

/** Every certificate-posture finding for one certificate, in a stable order. */
export function buildCertPostureFindings(cert: CertMetadata, issuerDn: string | null, caa: EffectiveCaa, nowSeconds: number): Finding[] {
	const ctx = buildPostureContext(cert.source);
	return [
		expiryFinding(ctx, cert, nowSeconds),
		keyStrengthFinding(ctx, cert),
		validityWindowFinding(ctx, cert),
		caaIssuerFinding(ctx, caa, issuerDn),
	];
}
