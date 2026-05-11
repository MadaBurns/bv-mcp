// SPDX-License-Identifier: BUSL-1.1

/**
 * Analytics Stream Hook (Private Layer Interface)
 *
 * This hook is dynamically injected in production builds. 
 * In OSS builds, this returns null/noop, ensuring no internal 
 * service bindings are required.
 */
interface AnalyticsHookEnv {
    BV_WEB?: { fetch: (input: RequestInfo, init?: RequestInit) => Promise<Response> };
    [key: string]: unknown;
}

export async function streamScanResult(env: AnalyticsHookEnv, payload: unknown): Promise<void> {
    // Check if the internal binding exists at runtime
    if (env.BV_WEB && typeof env.BV_WEB.fetch === 'function') {
        try {
            await env.BV_WEB.fetch('/internal/ingest/security-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (e) {
            console.error('Analytics stream failed:', e);
        }
    }
}
