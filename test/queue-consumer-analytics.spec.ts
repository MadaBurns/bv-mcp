// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { processScanMessage } from '../src/tenants/queue-consumer';
import * as analyticsHook from '../src/lib/hooks/analytics-stream';
import * as tenantResolver from '../src/tenants/tenant-resolver';
import { handleToolsCall } from '../src/handlers/tools';

vi.mock('../src/tenants/tenant-resolver');
vi.mock('../src/handlers/tools');

describe('Queue-Consumer Analytics Integration', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it('should trigger analytics stream after scan persistence', async () => {
        const streamSpy = vi.spyOn(analyticsHook, 'streamScanResult').mockResolvedValue();

        const mockDb = {
            prepare: vi.fn().mockReturnValue({
                bind: vi.fn().mockReturnThis(),
                first: vi.fn().mockResolvedValue(null), // no existing scan
                run: vi.fn().mockResolvedValue({ success: true }),
                all: vi.fn().mockResolvedValue({ results: [] })
            })
        };

        const mockTenant = {
            id: 'tenant-1',
            subTenantId: 'tenant-1',
            dbBinding: 'TENANT_DB_TENANT_1',
            // Phase 4: the consumer reads `tenant.db` (handle) instead of env[dbBinding].
            db: mockDb,
            tier: 'default'
        };
        vi.mocked(tenantResolver.resolveTenant).mockResolvedValue(mockTenant as unknown as Awaited<ReturnType<typeof tenantResolver.resolveTenant>>);

        const mockScanResult = { isError: false, result: {} };
        vi.mocked(handleToolsCall).mockResolvedValue(mockScanResult as unknown as Awaited<ReturnType<typeof handleToolsCall>>);

        const mockEnv = {
            BV_WEB: { fetch: vi.fn() },
            TENANT_REGISTRY_DB: mockDb,
            TENANT_DB_TENANT_1: mockDb,
            SCAN_CACHE: {},
        };

        const payload = {
            cycle_id: 'cycle-1',
            sub_tenant_id: 'tenant-1',
            domain: 'test.com'
        };

        const ctx = {
            waitUntil: vi.fn()
        };

        const outcome = await processScanMessage(payload, 1, mockEnv as unknown as Parameters<typeof processScanMessage>[2], ctx);
        
        expect(outcome).toBe('ack');
        expect(streamSpy).toHaveBeenCalledWith(mockEnv, expect.objectContaining({
            domain: 'test.com',
            sub_tenant_id: 'tenant-1',
            cycle_id: 'cycle-1'
        }));
    });
});
