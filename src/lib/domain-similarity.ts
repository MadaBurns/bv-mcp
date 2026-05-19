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
