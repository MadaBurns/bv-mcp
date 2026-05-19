// SPDX-License-Identifier: BUSL-1.1

import type { BrandAuditReportEnvelope } from './mcp-http-client';

export function extractEmbeddedBrandAuditResult(envelope: BrandAuditReportEnvelope): BrandAuditReportEnvelope['findings'][number]['metadata']['result'] | null {
	const summary = envelope.findings.find((finding) => finding.metadata?.summary === true);
	return summary?.metadata?.result ?? null;
}

export async function fetchBrandAuditReportWithRetry(options: {
	auditId: string;
	target: string;
	callTool: (args: { auditId: string; target: string }) => Promise<BrandAuditReportEnvelope>;
	attempts?: number;
	delayMs?: number;
	wait?: (ms: number) => Promise<void>;
	onRetry?: (attempt: number, envelope: BrandAuditReportEnvelope) => void;
}): Promise<{ envelope: BrandAuditReportEnvelope; result: NonNullable<ReturnType<typeof extractEmbeddedBrandAuditResult>> }> {
	const attempts = options.attempts ?? 6;
	const delayMs = options.delayMs ?? 1_000;
	const wait = options.wait ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
	let lastEnvelope: BrandAuditReportEnvelope | null = null;

	for (let attempt = 1; attempt <= attempts; attempt++) {
		const envelope = await options.callTool({ auditId: options.auditId, target: options.target });
		lastEnvelope = envelope;
		const result = extractEmbeddedBrandAuditResult(envelope);
		if (result) return { envelope, result };
		if (attempt < attempts) {
			options.onRetry?.(attempt, envelope);
			await wait(delayMs);
		}
	}

	const summary = lastEnvelope?.findings.find((finding) => finding.metadata?.summary === true);
	const status = summary?.metadata?.status ?? 'missing';
	throw new Error(`brand_audit_get_report missing embedded result after ${attempts} attempt(s): auditId=${options.auditId} target=${options.target} status=${status}`);
}
