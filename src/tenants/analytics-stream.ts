// SPDX-License-Identifier: BUSL-1.1

export interface AnalyticsPayload {
    domain: string;
    grade: string | null;
    score: number | null;
    sub_tenant_id: string;
    cycle_id: string;
}

export async function streamAnalyticsEvent(
    bvWebBinding: { fetch: (url: string, init: RequestInit) => Promise<Response> },
    payload: AnalyticsPayload
): Promise<boolean> {
    try {
        const response = await bvWebBinding.fetch('/internal/ingest/security-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return response.ok;
    } catch (e) {
        console.error('Analytics stream failed:', e);
        return false;
    }
}
