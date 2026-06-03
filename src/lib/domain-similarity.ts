// SPDX-License-Identifier: BUSL-1.1

function label(domain: string): string {
	return domain.trim().toLowerCase().replace(/\.+$/, '').split('.')[0] ?? '';
}

function levenshtein(a: string, b: string): number {
	const dp = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
	for (let i = 0; i <= a.length; i++) dp[i][0] = i;
	for (let j = 0; j <= b.length; j++) dp[0][j] = j;
	for (let i = 1; i <= a.length; i++) {
		for (let j = 1; j <= b.length; j++) {
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
		}
	}
	return dp[a.length][b.length];
}

export function domainLabelSimilarity(target: string, candidate: string): number {
	const left = label(target);
	const right = label(candidate);
	if (!left || !right) return 0;
	const maxLen = Math.max(left.length, right.length);
	return Math.round((1 - levenshtein(left, right) / maxLen) * 100) / 100;
}

// ---------------------------------------------------------------------------
// Combosquat detection
//
// Whole-label edit distance (`domainLabelSimilarity`) cannot see `paypal` inside
// `paypal-login` — appending a token inflates the denominator and collapses the
// score below any useful threshold. Combosquats are instead detected by treating
// the label as a token sequence and asking whether the brand token appears as a
// bounded segment alongside ≥1 other token. See `combosquatMatch`.
// ---------------------------------------------------------------------------

/**
 * KNOB (yours to tune): lure keywords that signal credential-phishing intent.
 *
 * Two jobs: (1) escalate combosquat severity when an extra token is one of these,
 * and (2) gate the collision-prone undelimited branch (a concatenated match only
 * counts when the non-brand remainder is exactly one of these words).
 *
 * Keep entries lowercase and singular. Adding a generic word here (e.g. `app`,
 * `web`) widens recall but raises false positives on the undelimited branch.
 */
const LURE_KEYWORDS: ReadonlySet<string> = new Set([
	'login',
	'signin',
	'logon',
	'secure',
	'security',
	'verify',
	'verification',
	'account',
	'support',
	'help',
	'billing',
	'pay',
	'payment',
	'update',
	'confirm',
	'service',
	'auth',
	'sso',
	'mail',
	'webmail',
	'portal',
	'wallet',
	'recovery',
	'alert',
]);

/**
 * KNOB (yours to tune): minimum brand-token length for a *delimited* segment
 * match (`brand` is its own hyphen/dot/underscore segment). Below this, short
 * brand tokens collide with ordinary words too often (`hp`, `ge`, `bp`).
 */
const COMBOSQUAT_MIN_DELIMITED_LEN = 4;

/**
 * KNOB (yours to tune): minimum brand-token length for an *undelimited* match
 * (`brand` concatenated with a lure keyword, no separator). Stricter than the
 * delimited case because concatenation is inherently more collision-prone.
 * Set this to `Infinity` to disable the undelimited branch entirely (i.e. only
 * ever match clean `brand-keyword` segments — the lowest-false-positive mode).
 */
const COMBOSQUAT_MIN_UNDELIMITED_LEN = 6;

export interface CombosquatMatch {
	/** The brand token that was found within the candidate label. */
	brandToken: string;
	/** Every label token that is NOT the brand token. */
	extraTokens: string[];
	/** True when at least one extra token is a known lure keyword. */
	hasLureKeyword: boolean;
	/** Whether the brand token was found as a delimited segment or concatenated. */
	matchKind: 'delimited' | 'undelimited';
}

/** Split a label into tokens on hyphen / underscore / dot runs, dropping empties. */
function splitLabelTokens(label: string): string[] {
	return label
		.split(/[-_.]+/)
		.map((t) => t.trim())
		.filter((t) => t.length > 0);
}

/**
 * Detect whether `candidateLabel` is a combosquat of `brandToken` — i.e. the
 * brand token appears as a bounded segment of a longer label alongside at least
 * one other token (`paypal-login`, `login-paypal`, `paypallogin`).
 *
 * Callers pass already-extracted labels (e.g. via `extractBrandName`), not full
 * domains, so this stays dependency-free. An exact label match (`paypal` ===
 * `paypal`) returns null — that is an owned portfolio domain, not a combosquat.
 *
 * Returns the match detail (for finding reasons + severity) or null.
 */
export function combosquatMatch(brandToken: string, candidateLabel: string): CombosquatMatch | null {
	const brand = brandToken.trim().toLowerCase();
	const label = candidateLabel.trim().toLowerCase();
	if (!brand || !label || label === brand) return null;

	// Delimited: brand token is its own segment, with ≥1 sibling token.
	if (brand.length >= COMBOSQUAT_MIN_DELIMITED_LEN) {
		const tokens = splitLabelTokens(label);
		if (tokens.length >= 2 && tokens.includes(brand)) {
			const extraTokens = tokens.filter((t) => t !== brand);
			return {
				brandToken: brand,
				extraTokens,
				hasLureKeyword: extraTokens.some((t) => LURE_KEYWORDS.has(t)),
				matchKind: 'delimited',
			};
		}
	}

	// Undelimited: brand token concatenated with a single lure keyword and no
	// separator. The exact-keyword test on the remainder is what keeps this from
	// firing on innocent substrings (`fabricpay`, `pineapple`, `paypalways`).
	if (brand.length >= COMBOSQUAT_MIN_UNDELIMITED_LEN) {
		const remainder = label.startsWith(brand)
			? label.slice(brand.length)
			: label.endsWith(brand)
				? label.slice(0, label.length - brand.length)
				: null;
		if (remainder && LURE_KEYWORDS.has(remainder)) {
			return { brandToken: brand, extraTokens: [remainder], hasLureKeyword: true, matchKind: 'undelimited' };
		}
	}

	return null;
}
