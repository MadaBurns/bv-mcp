// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi } from 'vitest';
import { streamAnalyticsEvent } from '../src/tenants/analytics-stream';

describe('Analytics Pipeline', () => {
    it('should format payload correctly for bv-web ingestion', async () => {
        const mockEnv = {
            BV_WEB: {
                fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }))
            }
        };
        
        const payload = {
            domain: 'example.com',
            grade: 'A',
            score: 95,
            sub_tenant_id: 'tenant-example',
            cycle_id: 'cycle-123'
        };

        const result = await streamAnalyticsEvent(mockEnv.BV_WEB as any, payload);
        
        expect(result).toBe(true);
        expect(mockEnv.BV_WEB.fetch).toHaveBeenCalledWith(
            expect.stringContaining('/internal/ingest/security-scan'),
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify(payload)
            })
        );
    });
});
