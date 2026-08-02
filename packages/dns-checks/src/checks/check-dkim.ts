// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM (DomainKeys Identified Mail) check.
 * Queries common DKIM selector TXT records and validates configuration.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import {
	analyzeHashRestriction,
	analyzeKeyStrength,
	analyzeServiceTypes,
	consolidateSelectorProbeKeyStrengthFindings,
	getDkimTagValue,
	parseDkimFlags,
} from './dkim-analysis';
import { COMMON_DKIM_SELECTORS } from './dkim-selectors';
import { attributeCnameChain } from './dkim-saas-attribution';

/** Maximum CNAME hops to follow when probing a selector. */
const MAX_CNAME_HOPS = 5;

/**
 * Probe a selector's TXT record and, only if records are found, walk the
 * CNAME chain to populate `chain` for SaaS attribution.
 *
 * The DNS query function may transparently follow CNAMEs when answering a
 * TXT query (most DoH resolvers do), so the chain walk via explicit CNAME
 * queries is the only way to recover the delegation path. We restrict
 * those extra queries to selectors that actually returned TXT records, so
 * the negative-probe path (the common case) still costs one query per
 * selector.
 */
async function probeSelectorWithCname(
	queryDNS: DNSQueryFunction,
	name: string,
	timeout: number,
): Promise<{ records: string[]; chain: string[] }> {
	let records: string[] = [];
	try {
		const txt = await queryDNS(name, 'TXT', { timeout });
		records = txt.filter((r) => r.toLowerCase().includes('v=dkim1') || r.includes('p='));
	} catch {
		records = [];
	}
	if (records.length === 0) return { records, chain: [] };

	const chain: string[] = [];
	let current = name;
	for (let hop = 0; hop < MAX_CNAME_HOPS; hop++) {
		let target: string | undefined;
		try {
			const cnameAnswers = await queryDNS(current, 'CNAME', { timeout });
			target = cnameAnswers[0]?.replace(/\.$/, '');
		} catch {
			target = undefined;
		}
		if (!target) break;
		chain.push(target);
		current = target;
	}
	return { records, chain };
}

/**
 * Check DKIM records for a domain.
 * Probes common selectors at <selector>._domainkey.<domain>.
 * Optionally accepts a specific selector to check.
 */
export async function checkDKIM(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; selector?: string },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const selector = options?.selector;
	const findings: Finding[] = [];
	const selectorsToCheck = selector ? [selector] : [...COMMON_DKIM_SELECTORS];
	const foundSelectors: string[] = [];
	let hasValidKey = false;

	// Check each selector in parallel (TXT + CNAME chain for SaaS attribution)
	const results = await Promise.all(
		selectorsToCheck.map(async (sel) => {
			const name = `${sel}._domainkey.${domain}`;
			const { records, chain } = await probeSelectorWithCname(queryDNS, name, timeout);
			return { selector: sel, records, chain };
		}),
	);

	for (const result of results) {
		if (result.records.length > 0) {
			foundSelectors.push(result.selector);
			const delegatedTo = attributeCnameChain(result.chain);

			// Multiple DKIM RRs published at one selector.
			// RFC 6376 §3.6.2 (Resource Record Types for Key Storage) leaves verifier
			// behaviour undefined when a selector resolves to
			// more than one key record, so which key validates a signature is not something the
			// domain owner controls. This is NOT the long-key-split case: the resolver layer
			// rejoins the multiple character-strings of a single TXT RR before we see it, so two
			// surviving DKIM-shaped entries here are two distinct RRs — the shape a stale key left
			// behind by a half-finished rotation takes, and the shape an injected rogue key would
			// take alongside the legitimate one.
			if (result.records.length > 1) {
				findings.push(
					createFinding(
						'dkim',
						`Multiple DKIM records at one selector: ${result.selector}`,
						'low',
						`DKIM selector "${result.selector}" publishes ${result.records.length} separate key records. RFC 6376 §3.6.2 leaves it undefined which one a verifier uses, so signing outcomes are not deterministic — a stale key from an incomplete rotation can validate signatures the current key would reject. Publish exactly one key record per selector and use a fresh selector name to rotate.`,
						{
							recordCount: result.records.length,
							selector: result.selector,
							...(delegatedTo ? { delegatedTo } : {}),
						},
					),
				);
			}

			// Validate each DKIM record
			for (const record of result.records) {
				const isRevoked = /p=\s*;/i.test(record) || /p=\s*$/i.test(record);
				const publicKey = getDkimTagValue(record, 'p');

				// Check for empty public key (revoked)
				if (isRevoked) {
					findings.push(
						createFinding(
							'dkim',
							`Revoked DKIM key: ${result.selector}`,
							'medium',
							`DKIM selector "${result.selector}" has an empty public key (p=), indicating the key has been revoked.`,
						),
					);
				} else {
					hasValidKey = true;
				}

				// Check key type (should be rsa or ed25519)
				const keyTypeMatch = record.match(/k=([^;\s]+)/i);
				const parsedKeyType = keyTypeMatch ? keyTypeMatch[1].toLowerCase() : null;
				if (keyTypeMatch && !['rsa', 'ed25519'].includes(parsedKeyType!)) {
					findings.push(
						createFinding(
							'dkim',
							`Unknown DKIM key type: ${keyTypeMatch[1]}`,
							'medium',
							`DKIM selector "${result.selector}" uses unknown key type "${keyTypeMatch[1]}". Expected "rsa" or "ed25519".`,
						),
					);
				}

				// Check for testing mode.
				// Tag-aware parse rather than a bare /t=y/ scan: RFC 6376 §3.6.1 makes `t=` a
				// colon-separated flag list in ANY order, so `t=s:y` is exactly as much test
				// mode as `t=y:s` — the old substring test saw only the latter. It also stops a
				// `t=y` substring inside the free-text `n=` notes tag from inventing a finding.
				if (parseDkimFlags(record).testMode) {
					findings.push(
						createFinding(
							'dkim',
							`DKIM in testing mode: ${result.selector}`,
							'low',
							`DKIM selector "${result.selector}" is in testing mode (t=y). Verifiers may treat failures as non-fatal.`,
						),
					);
				}

				// Analyze key strength (only if key is valid/not revoked)
				if (!isRevoked && publicKey) {
					const declaredKeyType = parsedKeyType ?? 'rsa-default';
					const keyAnalysis = analyzeKeyStrength(publicKey, declaredKeyType);

					if (keyAnalysis.keyType === 'ed25519') {
						findings.push(
							createFinding(
								'dkim',
								`Ed25519 key detected: ${result.selector}`,
								'info',
								`DKIM selector "${result.selector}" uses Ed25519, a strong elliptic-curve key type.`,
								{
									keyType: 'ed25519',
									selector: result.selector,
								},
							),
						);
					} else if (keyAnalysis.keyType === 'unknown') {
						findings.push(
							createFinding(
								'dkim',
								`Short key material: ${result.selector}`,
								'medium',
								`DKIM selector "${result.selector}" has very short key material without a k= tag. Consider adding "k=ed25519" or "k=rsa" for clarity.`,
								{
									selector: result.selector,
								},
							),
						);
					} else if (keyAnalysis.keyType === 'rsa-malformed') {
						findings.push(
							createFinding(
								'dkim',
								`Malformed DKIM key: ${result.selector}`,
								'medium',
								`DKIM selector "${result.selector}" declares a ~${keyAnalysis.bits}-bit RSA key but the published key material is truncated or incomplete in DNS — commonly caused by splitting the key across multiple TXT records instead of one. DKIM signature verification fails until the full public key is republished as a single TXT record (RFC 6376 §3.6.2).`,
								{
									estimatedBits: keyAnalysis.bits,
									keyType: 'rsa-malformed',
									selector: result.selector,
									...(delegatedTo ? { delegatedTo } : {}),
								},
							),
						);
					} else if (keyAnalysis.keyType === 'rsa') {
						const severityMsg =
							keyAnalysis.strength === 'critical'
								? 'weak'
								: keyAnalysis.strength === 'high'
									? 'legacy'
									: keyAnalysis.strength === 'medium'
										? 'below recommended'
										: 'strong';
						const descriptions: Record<string, string> = {
							critical: `DKIM RSA key for "${result.selector}" is ${severityMsg} (~${keyAnalysis.bits} bits). Upgrade to 2048-bit RSA or use Ed25519 for better security.`,
							high: `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). Consider upgrading to 2048-bit RSA or Ed25519.`,
							medium: `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). Major providers recommend 4096-bit RSA or Ed25519.`,
							info: `DKIM RSA key for "${result.selector}" is strong (${keyAnalysis.bits} bits).`,
						};

						if (keyAnalysis.strength !== 'info') {
							// SaaS-delegated CNAME chains downgrade high → medium and
							// reframe the description to credit the provider.
							let severity = keyAnalysis.strength;
							let description = descriptions[keyAnalysis.strength];
							if (delegatedTo && severity === 'high') {
								severity = 'medium';
								description = `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). The selector is CNAME-delegated to ${delegatedTo} — only ${delegatedTo} can rotate this key; raise it with your provider.`;
							}
							findings.push(
								createFinding(
									'dkim',
									`${severityMsg.charAt(0).toUpperCase() + severityMsg.slice(1)} RSA key: ${result.selector}`,
									severity,
									description,
									{
										estimatedBits: keyAnalysis.bits,
										keyType: keyAnalysis.keyType,
										selector: result.selector,
										...(delegatedTo ? { delegatedTo } : {}),
									},
								),
							);
						}
					}
				}

				// Check for missing v= tag (should be v=DKIM1)
				const versionTag = getDkimTagValue(record, 'v');
				if (!versionTag) {
					if (delegatedTo) {
						// SaaS providers (notably SendGrid) ship records without v=DKIM1
						// by design — RFC 6376 §3.6.1 tolerates this. Downgrade to info
						// and credit the provider so the tenant doesn't waste cycles on
						// a record they can't change.
						findings.push(
							createFinding(
								'dkim',
								`Missing DKIM version tag: ${result.selector}`,
								'info',
								`DKIM selector "${result.selector}" is CNAME-delegated to ${delegatedTo} and the upstream record omits the v=DKIM1 tag. This is RFC 6376 §3.6.1-tolerated; only ${delegatedTo} can change it.`,
								{ delegatedTo, selector: result.selector },
							),
						);
					} else {
						findings.push(
							createFinding(
								'dkim',
								`Missing DKIM version tag: ${result.selector}`,
								'medium',
								`DKIM selector "${result.selector}" is missing the v= tag. Should be set to v=DKIM1.`,
							),
						);
					}
				}

				// Check the h= hash-algorithm restriction (RFC 8301).
				// h= restricts which hash algorithms this key will verify. Three unhealthy
				// shapes, only the first of which was previously detected.
				const hashRestriction = analyzeHashRestriction(record);
				if (hashRestriction) {
					if (hashRestriction.kind === 'sha1-only') {
						findings.push(
							createFinding(
								'dkim',
								`Deprecated hash algorithm (h=sha1): ${result.selector}`,
								// RFC 8301 §3.1: rsa-sha1 "MUST NOT be used" and signatures with it
								// "have permanently failed evaluation" → high, not medium.
								'high',
								`DKIM selector "${result.selector}" only accepts SHA-1 signatures (h=sha1). RFC 8301 §3.1 states SHA-1 MUST NOT be used and such signatures have permanently failed evaluation. Add sha256 to the h= tag or remove the restriction.`,
							),
						);
					} else if (hashRestriction.kind === 'no-sha256') {
						findings.push(
							createFinding(
								'dkim',
								`Hash restriction excludes SHA-256: ${result.selector}`,
								'medium',
								`DKIM selector "${result.selector}" restricts acceptable hash algorithms to "${hashRestriction.algorithms.join(':')}", which omits sha256. RFC 8301 §3.2 makes rsa-sha256 the mandatory-to-implement algorithm, so conforming signers and verifiers are turned away by this key. Add sha256 to the h= tag or drop the restriction.`,
								{
									hashAlgorithms: hashRestriction.algorithms,
									selector: result.selector,
									...(delegatedTo ? { delegatedTo } : {}),
								},
							),
						);
					} else {
						findings.push(
							createFinding(
								'dkim',
								`SHA-1 permitted alongside SHA-256: ${result.selector}`,
								'low',
								`DKIM selector "${result.selector}" advertises "${hashRestriction.algorithms.join(':')}", accepting SHA-1 in addition to SHA-256. Modern signatures still verify, but the key tells verifiers it will honour a hash RFC 8301 §3.1 prohibits — an avoidable downgrade surface. Remove sha1 from the h= tag.`,
								{
									hashAlgorithms: hashRestriction.algorithms,
									selector: result.selector,
									...(delegatedTo ? { delegatedTo } : {}),
								},
							),
						);
					}
				}

				// Check the s= service-type restriction (RFC 6376 §3.6.1, §6.1.2).
				// A list that admits neither "email" nor the "*" wildcard obliges verifiers to
				// ignore the key for mail — the record looks healthy in DNS while the selector
				// is inert for the one service it was almost certainly published to serve.
				const serviceTypes = analyzeServiceTypes(record);
				if (serviceTypes && !serviceTypes.coversEmail) {
					findings.push(
						createFinding(
							'dkim',
							`Service type excludes email: ${result.selector}`,
							'medium',
							`DKIM selector "${result.selector}" declares s=${serviceTypes.services.join(':')}, which admits neither "email" nor the "*" wildcard. RFC 6376 §6.1.2 obliges a verifier to ignore this key when validating mail, so signatures made with it do not authenticate. Set s=email or s=* (the default).`,
							{
								selector: result.selector,
								serviceTypes: serviceTypes.services,
								...(delegatedTo ? { delegatedTo } : {}),
							},
						),
					);
				}
			}
		}
	}

	// If multiple found selectors are ALL revoked and none have valid keys,
	// this is a non-sending domain posture — downgrade to info
	if (foundSelectors.length > 1 && !hasValidKey) {
		const revokedCount = findings.filter((f) => f.title.startsWith('Revoked DKIM key:')).length;
		// Remove individual revoked findings
		for (let i = findings.length - 1; i >= 0; i--) {
			if (findings[i].title.startsWith('Revoked DKIM key:')) {
				findings.splice(i, 1);
			}
		}
		findings.push(
			createFinding(
				'dkim',
				'DKIM keys revoked (non-sending)',
				'info',
				`All ${revokedCount} DKIM selector(s) have revoked keys (empty p= tag). This is expected for domains that do not send email.`,
			),
		);
	}

	// In selector-probing mode, multiple selectors can expose identical key profiles.
	if (!selector && foundSelectors.length > 1) {
		consolidateSelectorProbeKeyStrengthFindings(findings);
	}

	if (foundSelectors.length === 0) {
		findings.push(
			createFinding(
				'dkim',
				'No DKIM records found among tested selectors',
				'high',
				`No DKIM records were found for ${domain} among the tested selector set (${selectorsToCheck.join(', ')}). This result is based on selector probing and may miss custom selector names. DKIM helps verify email authenticity and integrity.`,
				{
					signalType: 'dkim',
					confidence: 'heuristic',
					detectionMethod: 'selector-probing',
					selectorsChecked: selectorsToCheck,
					selectorsFound: [],
				},
			),
		);
	} else if (foundSelectors.length > 0 && hasValidKey && findings.every((f) => f.severity === 'info')) {
		findings.push(
			createFinding('dkim', 'DKIM configured', 'info', `DKIM records found for selectors: ${foundSelectors.join(', ')}`, {
				signalType: 'dkim',
				selectorsChecked: selectorsToCheck,
				selectorsFound: foundSelectors,
			}),
		);
	}

	// controlPresent: an ACTIVE DKIM key was observed. All-revoked (empty p=) selectors count as
	// absent for profile detection — a revoked key is not a working hardening signal.
	const dkimControlPresent = foundSelectors.length > 0 && hasValidKey;
	const result = buildCheckResult('dkim', findings, dkimControlPresent);

	// Defect E — score floor on probe miss.
	// A HIGH "No DKIM records found" finding scores 75 by default (100 - 25),
	// which contradicts the HIGH severity. Cap at 50 when probing turned up
	// nothing so the score reflects the severity surface.
	if (foundSelectors.length === 0 && result.score > 50) {
		return { ...result, score: 50 };
	}

	return result;
}
