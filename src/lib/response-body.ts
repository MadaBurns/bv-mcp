// SPDX-License-Identifier: BUSL-1.1

export async function disposeUnreadResponseBody(response: Response): Promise<void> {
	if (!response.body) return;
	try {
		await response.body.cancel();
	} catch {
		// The body may already be locked or consumed.
	}
}
