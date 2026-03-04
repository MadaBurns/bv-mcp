# Post-Audit Fixes (v1.0.2) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 8 audit issues: remove upgrade CTA, update static resources, fix CHANGELOG typo, add HSTS/redirect checks, deepen MX validation, rename CATEGORY_DEFAULTS, expand explain_finding enum, add explanation entries, bump version.

**Architecture:** Sequential fixes to source + test files. Each fix is independent except Fix 8 (explanation entries) depends on Fix 4 (HSTS) and Fix 5 (MX) being done first. Tests run after each fix.

**Tech Stack:** TypeScript, Vitest, Cloudflare Workers runtime, Hono v4

---

### Task 1: Remove `upgrade_cta` from scan output (Fix 1)

**Files:**
- Modify: `src/tools/scan-domain.ts`
- Modify: `test/scan-domain.spec.ts`

**Step 1: Remove `upgrade_cta` from `ScanDomainResult` interface**

In `src/tools/scan-domain.ts`, remove line 34 (`upgrade_cta: string;`) from the interface:

```typescript
// BEFORE (lines 28-35):
export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	cached: boolean;
	timestamp: string;
	upgrade_cta: string;
}

// AFTER:
export interface ScanDomainResult {
	domain: string;
	score: ScanScore;
	checks: CheckResult[];
	cached: boolean;
	timestamp: string;
}
```

**Step 2: Remove `upgrade_cta` from the result object in `scanDomain()`**

In `src/tools/scan-domain.ts`, remove line 87 from the result literal:

```typescript
// BEFORE (lines 81-88):
	const result: ScanDomainResult = {
		domain: domain,
		score,
		checks: checkResults,
		cached: false,
		timestamp: new Date().toISOString(),
		upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically → https://blackveilsecurity.com',
	};

// AFTER:
	const result: ScanDomainResult = {
		domain: domain,
		score,
		checks: checkResults,
		cached: false,
		timestamp: new Date().toISOString(),
	};
```

**Step 3: Remove `upgrade_cta` reference from `formatScanReport()`**

In `src/tools/scan-domain.ts`, remove lines 221-222 (the CTA output at end of report):

```typescript
// REMOVE these two lines from formatScanReport():
	lines.push('---');
	lines.push(result.upgrade_cta);
```

**Step 4: Update test assertions in `test/scan-domain.spec.ts`**

4a. In the "returns result with correct structure" test (line 132), remove the 3 `upgrade_cta` assertions (lines 141-143):

```typescript
// REMOVE:
		expect(result).toHaveProperty('upgrade_cta');
		expect(typeof result.upgrade_cta).toBe('string');
		expect(result.upgrade_cta).toContain('blackveilsecurity.com');
```

4b. In the `formatScanReport` mock result (line 227), remove `upgrade_cta` property (line 253):

```typescript
// REMOVE from the mockResult object:
			upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically → https://blackveilsecurity.com',
```

Also remove the assertion lines 273-274:

```typescript
// REMOVE:
		expect(report).toContain('BLACKVEIL');
		expect(report).toContain('blackveilsecurity.com');
```

4c. In the second `formatScanReport` mock result ("includes cache notice" test, line 280), remove `upgrade_cta` property (line 303):

```typescript
// REMOVE from the mockResult object:
			upgrade_cta: 'This tool finds problems. BLACKVEIL fixes them automatically → https://blackveilsecurity.com',
```

**Step 5: Run tests**

Run: `npm test`
Expected: All tests pass

**Step 6: Commit**

```bash
git add src/tools/scan-domain.ts test/scan-domain.spec.ts
git commit -m "fix: remove upgrade_cta from scan output"
```

---

### Task 2: Update static resources to reflect 10 checks (Fix 2)

**Files:**
- Modify: `src/handlers/resources.ts`

**Step 1: Update the security-checks resource content**

In `src/handlers/resources.ts`, in the `RESOURCE_CONTENT` object for `dns-security://guides/security-checks`:

1a. Change the Composite Tools section (line 107) from:
```
- \`scan_domain\`: Runs all 8 category checks and produces an overall score + grade.
```
to:
```
- \`scan_domain\`: Runs all 10 checks (8 category checks + MX + Subdomain Takeover) and produces an overall score + grade.
```

1b. Add MX and Subdomain Takeover sections before the `## Composite Tools` section (before line 105):

```markdown
## MX (Mail Exchange)
Tool: \`check_mx\`
Validates presence and quality of MX records for a domain, including outbound email provider detection.

## Subdomain Takeover Detection
Tool: internal to \`scan_domain\` (not directly callable)
Scans known subdomains for dangling CNAME records pointing to unresolved third-party services.

```

**Step 2: Update the scoring resource content**

In `src/handlers/resources.ts`, in the `RESOURCE_CONTENT` object for `dns-security://guides/scoring`, add MX and Subdomain Takeover to the importance weights table (after the CAA row, before the empty line):

```
| Subdomain Takeover | 0 (informational) |
| MX | 0 (informational) |
```

**Step 3: Run tests**

Run: `npm test`
Expected: All tests pass (no tests assert on "8 category" text)

**Step 4: Commit**

```bash
git add src/handlers/resources.ts
git commit -m "docs: update static resources to reflect 10 checks"
```

---

### Task 3: Fix CHANGELOG rate limit typo (Fix 3)

**Files:**
- Modify: `CHANGELOG.md`

**Step 1: Change `50 req/hr` to `100 req/hr`**

In `CHANGELOG.md` line 17, change:
```
- KV-backed per-IP rate limiting (10 req/min, 50 req/hr) with in-memory fallback
```
to:
```
- KV-backed per-IP rate limiting (10 req/min, 100 req/hr) with in-memory fallback
```

**Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "fix: correct rate limit typo in CHANGELOG (50 → 100 req/hr)"
```

---

### Task 4: Add HSTS header check and HTTP→HTTPS redirect to `check_ssl` (Fix 4)

**Files:**
- Modify: `src/tools/check-ssl.ts`
- Modify: `test/check-ssl.spec.ts`

**Step 1: Rewrite `src/tools/check-ssl.ts`**

Replace the entire file with:

```typescript
/**
 * SSL/TLS certificate check tool.
 * Validates SSL certificate by attempting HTTPS connection,
 * checks HSTS headers, and verifies HTTP→HTTPS redirect.
 * Workers-compatible: uses fetch API only.
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP→HTTPS redirect.
 */
export async function checkSsl(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	const httpsResult = await checkHttps(domain);
	findings.push(...httpsResult);

	// Only check HTTP redirect if HTTPS is working (no critical findings)
	const hasCritical = findings.some((f) => f.severity === 'critical');
	if (!hasCritical) {
		const redirectResult = await checkHttpRedirect(domain);
		findings.push(...redirectResult);
	}

	if (findings.length === 0) {
		findings.push(createFinding('ssl', 'SSL/TLS properly configured', 'info', `HTTPS is accessible for ${domain} with HSTS enabled.`));
	}

	return buildCheckResult('ssl', findings);
}

/** Check HTTPS connectivity by attempting a fetch */
async function checkHttps(domain: string): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const response = await fetch(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'follow',
			signal: AbortSignal.timeout(10_000),
		});

		// Check if we got redirected to HTTP (downgrade)
		if (response.url && response.url.startsWith('http://')) {
			findings.push(
				createFinding(
					'ssl',
					'HTTPS redirects to HTTP',
					'critical',
					`${domain} redirects HTTPS requests to HTTP, exposing traffic to interception.`,
				),
			);
		}

		// Check for HSTS header
		const hstsHeader = response.headers.get('strict-transport-security');
		if (!hstsHeader) {
			findings.push(
				createFinding(
					'ssl',
					'No HSTS header',
					'medium',
					`${domain} does not set a Strict-Transport-Security header. HSTS prevents browsers from connecting over plain HTTP.`,
				),
			);
		} else {
			// Check max-age value
			const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
			if (maxAgeMatch) {
				const maxAge = parseInt(maxAgeMatch[1], 10);
				if (maxAge < 31536000) {
					findings.push(
						createFinding(
							'ssl',
							'HSTS max-age too short',
							'low',
							`HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Recommended minimum is 31536000 (1 year).`,
						),
					);
				}
			}

			// Check for includeSubDomains
			if (!/includeSubDomains/i.test(hstsHeader)) {
				findings.push(
					createFinding(
						'ssl',
						'HSTS missing includeSubDomains',
						'low',
						`HSTS header does not include the includeSubDomains directive. Subdomains are not protected by HSTS.`,
					),
				);
			}
		}
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);

		if (message.includes('timeout') || message.includes('abort')) {
			findings.push(
				createFinding(
					'ssl',
					'HTTPS connection timeout',
					'high',
					`Could not establish HTTPS connection to ${domain} within 10 seconds. The server may not support HTTPS.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'ssl',
					'HTTPS connection failed',
					'critical',
					`Failed to connect to ${domain} over HTTPS: ${message}. The domain may not have a valid SSL certificate.`,
				),
			);
		}
	}

	return findings;
}

/** Check if HTTP redirects to HTTPS */
async function checkHttpRedirect(domain: string): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const response = await fetch(`http://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(10_000),
		});
		// 3xx with Location header pointing to HTTPS = good
		const location = response.headers.get('location');
		if (response.status >= 300 && response.status < 400 && location?.startsWith('https://')) {
			// Good — HTTP redirects to HTTPS
		} else if (response.status >= 300 && response.status < 400 && location && !location.startsWith('https://')) {
			findings.push(
				createFinding(
					'ssl',
					'HTTP does not redirect to HTTPS',
					'medium',
					`HTTP requests to ${domain} redirect to ${location} instead of HTTPS.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'ssl',
					'No HTTP to HTTPS redirect',
					'medium',
					`HTTP requests to ${domain} are not redirected to HTTPS (status ${response.status}).`,
				),
			);
		}
	} catch {
		// HTTP not available or blocked — not necessarily an issue, skip silently
	}
	return findings;
}
```

**Step 2: Rewrite `test/check-ssl.spec.ts`**

Replace the entire file with:

```typescript
import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkSsl', () => {
	async function run(domain = 'example.com') {
		const { checkSsl } = await import('../src/tools/check-ssl');
		return checkSsl(domain);
	}

	it('should return info finding when HTTPS connection succeeds with HSTS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			// HTTP redirect check
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		expect(result.category).toBe('ssl');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/properly configured/i);
		expect(result.passed).toBe(true);
	});

	it('should return critical finding when HTTPS redirects to HTTP', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'http://example.com/',
					ok: true,
					status: 200,
					headers: new Headers(),
				});
			}
			return Promise.reject(new Error('HTTP blocked'));
		});
		const result = await run();
		const finding = result.findings.find((f) => /redirects to HTTP/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return high finding on connection timeout', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted due to timeout'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toMatch(/timeout/i);
	});

	it('should return critical finding on connection failure', async () => {
		mockFetchError(new Error('ECONNREFUSED'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/failed/i);
	});

	it('should return medium finding when HSTS header is missing', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers(),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HSTS header');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return low finding when HSTS max-age is too short', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=3600; includeSubDomains' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'HSTS max-age too short');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return low finding when HSTS missing includeSubDomains', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'HSTS missing includeSubDomains');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should not produce redirect finding when HTTP redirects to HTTPS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const redirectFinding = result.findings.find((f) => f.title.includes('redirect'));
		expect(redirectFinding).toBeUndefined();
	});

	it('should return medium finding when no HTTP to HTTPS redirect', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			// HTTP returns 200 instead of redirect
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers(),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HTTP to HTTPS redirect');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});
});
```

**Step 3: Update the scan-domain test mocks and handlers-tools test mocks**

The SSL check mock in `test/scan-domain.spec.ts` and `test/handlers-tools.spec.ts` returns `httpResponse('OK')` for HTTPS URLs. This lacks `headers` property, so `response.headers.get('strict-transport-security')` will throw. We need to update the `httpResponse` helper in `test/scan-domain.spec.ts` to include a `headers` property with HSTS:

In `test/scan-domain.spec.ts`, update the `httpResponse` helper (lines 46-53):

```typescript
// BEFORE:
function httpResponse(body: string, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
	} as unknown as Response;
}

// AFTER:
function httpResponse(body: string, status = 200, headers?: Headers) {
	return {
		ok: status >= 200 && status < 300,
		status,
		headers: headers ?? new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
	} as unknown as Response;
}
```

Also add `url` property to HTTPS responses in `mockAllChecks` (line 117-119) and `mockWithOverrides` (line 364):

In `mockAllChecks`, change the HTTPS block (line 117-119):
```typescript
// BEFORE:
		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}

// AFTER:
		if (url.startsWith('https://')) {
			return Promise.resolve({ ...httpResponse('OK'), url });
		}
```

Do the same in `mockWithOverrides` (line 364):
```typescript
// BEFORE:
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));

// AFTER:
			if (url.startsWith('https://')) return Promise.resolve({ ...httpResponse('OK'), url });
```

And in the non-mail subdomain mock `mockNonMailSubdomain` (line 553):
```typescript
// BEFORE:
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));

// AFTER:
			if (url.startsWith('https://')) return Promise.resolve({ ...httpResponse('OK'), url });
```

And in the DNS error test's inline mock (line 639):
```typescript
// BEFORE:
			if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));

// AFTER:
			if (url.startsWith('https://')) return Promise.resolve({ ...httpResponse('OK'), url });
```

In `test/handlers-tools.spec.ts`, update the `httpResponse` helper (lines 37-44):
```typescript
// BEFORE:
function httpResponse(body: string, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
	} as unknown as Response;
}

// AFTER:
function httpResponse(body: string, status = 200, headers?: Headers) {
	return {
		ok: status >= 200 && status < 300,
		status,
		headers: headers ?? new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
	} as unknown as Response;
}
```

Add `url` property for HTTPS returns in `mockAllChecks` in handlers-tools (lines 82-84):
```typescript
// BEFORE:
		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}

// AFTER:
		if (url.startsWith('https://')) {
			return Promise.resolve({ ...httpResponse('OK'), url });
		}
```

Update the `check_ssl` test mock (lines 155-163) in handlers-tools to include headers and url:
```typescript
// BEFORE:
	it('check_ssl with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			text: () => Promise.resolve('OK'),
			json: () => Promise.resolve({}),
		} as unknown as Response);

// AFTER:
	it('check_ssl with valid domain returns content', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url,
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
					text: () => Promise.resolve('OK'),
					json: () => Promise.resolve({}),
				} as unknown as Response);
			}
			// HTTP redirect check
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: `https://${new URL(url).hostname}/` }),
				text: () => Promise.resolve(''),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		});
```

**Step 4: Run tests**

Run: `npm test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/tools/check-ssl.ts test/check-ssl.spec.ts test/scan-domain.spec.ts test/handlers-tools.spec.ts
git commit -m "feat: add HSTS header validation and HTTP→HTTPS redirect check to check_ssl"
```

---

### Task 5: Deepen `check_mx` validation (Fix 5)

**Files:**
- Modify: `src/tools/check-mx.ts`
- Modify: `test/check-mx.spec.ts`

**Step 1: Replace `src/tools/check-mx.ts`**

Replace the entire file with:

```typescript
/**
 * MX record check tool for MCP server.
 * Validates presence and quality of MX records for a domain.
 * Returns CheckResult with findings including RFC compliance, redundancy, and provider detection.
 */
import type { CheckResult, Finding } from '../lib/scoring';
import { createFinding, buildCheckResult } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';

/** Check MX record configuration for a domain */
export async function checkMx(domain: string): Promise<CheckResult> {
	let answers;
	try {
		answers = await queryDnsRecords(domain, 'MX');
	} catch {
		return buildCheckResult('mx', [createFinding('mx', 'DNS query failed', 'high', 'MX record lookup failed')]);
	}

	if (!answers || answers.length === 0) {
		return buildCheckResult('mx', [
			createFinding(
				'mx',
				'No MX records found',
				'medium',
				'No mail exchange records present. If this domain does not handle email, consider publishing a null MX record (RFC 7505).',
			),
		]);
	}

	const findings: Finding[] = [];

	// Parse MX records into priority + exchange pairs
	const mxRecords = answers.map((a) => {
		const parts = a.split(' ');
		const priority = parseInt(parts[0], 10);
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { priority, exchange, raw: a };
	});

	// Check for null MX (RFC 7505: priority 0, exchange ".")
	const nullMx = mxRecords.find((r) => r.exchange === '' || r.exchange === '.');
	if (nullMx) {
		findings.push(
			createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.'),
		);
		return buildCheckResult('mx', findings);
	}

	findings.push(createFinding('mx', 'MX records found', 'info', `${mxRecords.length} mail exchange record(s) present.`));

	// Check for MX pointing to IP address (invalid per RFC 5321 §5.1)
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	for (const mx of mxRecords) {
		if (ipPattern.test(mx.exchange)) {
			findings.push(
				createFinding(
					'mx',
					'MX points to IP address',
					'high',
					`MX record "${mx.raw}" points to an IP address. MX targets must be hostnames per RFC 5321.`,
				),
			);
		}
	}

	// Check for single MX (no redundancy)
	if (mxRecords.length === 1) {
		findings.push(createFinding('mx', 'Single MX record', 'low', 'Only one MX record found. Consider adding a backup MX for redundancy.'));
	}

	// Check for duplicate priorities
	const priorities = mxRecords.map((r) => r.priority);
	const uniquePriorities = new Set(priorities);
	if (uniquePriorities.size < priorities.length && mxRecords.length > 1) {
		findings.push(
			createFinding(
				'mx',
				'Duplicate MX priorities',
				'low',
				'Multiple MX records share the same priority. This provides round-robin load balancing but no clear failover order.',
			),
		);
	}

	// Detect known outbound email providers
	const outboundProviders = [
		'google.com',
		'googlemail.com',
		'outlook.com',
		'mailgun.org',
		'sendgrid.net',
		'amazonses.com',
		'pphosted.com',
		'mimecast.com',
	];
	const mxTargets = mxRecords.map((r) => r.exchange);
	const outbound = mxTargets.some((t) => outboundProviders.some((p) => t.endsWith(p)));
	if (outbound) {
		findings.push(createFinding('mx', 'Managed email provider detected', 'info', 'MX points to a known managed email provider.'));
	}

	return buildCheckResult('mx', findings);
}
```

**Step 2: Rewrite `test/check-mx.spec.ts`**

Replace the entire file with:

```typescript
import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function mockMxRecords(domain: string, records: string[]) {
	const answers = records.map((data) => ({
		name: domain,
		type: 15,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: domain, type: 15 }], answers));
}

describe('checkMx', () => {
	async function run(domain = 'example.com') {
		const { checkMx } = await import('../src/tools/check-mx');
		return checkMx(domain);
	}

	it('should return medium finding if no MX records found', async () => {
		mockMxRecords('nomx.com', []);
		const result = await run('nomx.com');
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toMatch(/No MX records found/i);
	});

	it('should return pass if MX records found', async () => {
		mockMxRecords('hasmx.com', ['10 mx1.hasmx.com.', '20 mx2.hasmx.com.']);
		const result = await run('hasmx.com');
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toMatch(/MX records found/i);
	});

	it('should detect managed email provider', async () => {
		mockMxRecords('outbound.com', ['10 aspmx.l.google.com.']);
		const result = await run('outbound.com');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.includes('provider'));
		expect(infoFinding).toBeTruthy();
		expect(infoFinding!.title).toMatch(/Managed email provider detected/i);
	});

	it('returns correct category', async () => {
		mockMxRecords('example.com', ['10 mx.example.com.']);
		const result = await run('example.com');
		expect(result.category).toBe('mx');
	});

	it('should detect null MX record (RFC 7505)', async () => {
		mockMxRecords('nullmx.com', ['0 .']);
		const result = await run('nullmx.com');
		const finding = result.findings.find((f) => f.title === 'Null MX record (RFC 7505)');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should flag MX pointing to IP address as high severity', async () => {
		mockMxRecords('ipmx.com', ['10 192.168.1.1']);
		const result = await run('ipmx.com');
		const finding = result.findings.find((f) => f.title === 'MX points to IP address');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should flag single MX record as low severity', async () => {
		mockMxRecords('single.com', ['10 mx.single.com.']);
		const result = await run('single.com');
		const finding = result.findings.find((f) => f.title === 'Single MX record');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should flag duplicate MX priorities as low severity', async () => {
		mockMxRecords('dupes.com', ['10 mx1.dupes.com.', '10 mx2.dupes.com.']);
		const result = await run('dupes.com');
		const finding = result.findings.find((f) => f.title === 'Duplicate MX priorities');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});
});
```

**Step 3: Run tests**

Run: `npm test`
Expected: All tests pass. Note: The non-mail domain detection in `scan-domain.ts` checks by title string (`f.title === 'No MX records found'`), not by severity, so the severity change from `high` to `medium` does NOT break it.

**Step 4: Commit**

```bash
git add src/tools/check-mx.ts test/check-mx.spec.ts
git commit -m "feat: deepen check_mx validation with RFC 7505, IP detection, redundancy checks"
```

---

### Task 6: Rename `CATEGORY_DEFAULTS` to `CATEGORY_DISPLAY_WEIGHTS` (Fix 6)

**Files:**
- Modify: `src/lib/scoring.ts`
- Modify: `test/scoring.spec.ts`

**Step 1: Rename in `src/lib/scoring.ts`**

Change the const name and add a JSDoc comment. In `src/lib/scoring.ts`:

```typescript
// BEFORE (lines 38-50):
/** Default category score initialization values (all categories start at 0). The actual scoring weights are in IMPORTANCE_WEIGHTS. */
export const CATEGORY_DEFAULTS: Record<CheckCategory, number> = {

// AFTER:
/** Display/UI weight distribution for categories. NOT used in scoring — see IMPORTANCE_WEIGHTS for actual scoring weights. Exists for category registry and display purposes only. */
export const CATEGORY_DISPLAY_WEIGHTS: Record<CheckCategory, number> = {
```

Also update references inside `computeScanScore()` (lines 148 and 161):

```typescript
// BEFORE:
		for (const cat of Object.keys(CATEGORY_DEFAULTS) as CheckCategory[]) {
// AFTER:
		for (const cat of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
```

(Two occurrences)

**Step 2: Update `test/scoring.spec.ts`**

Change the import (line 2):

```typescript
// BEFORE:
import { buildCheckResult, createFinding, computeCategoryScore, computeScanScore, CATEGORY_DEFAULTS } from '../src/lib/scoring';

// AFTER:
import { buildCheckResult, createFinding, computeCategoryScore, computeScanScore, CATEGORY_DISPLAY_WEIGHTS } from '../src/lib/scoring';
```

Change the test reference (line 107):

```typescript
// BEFORE:
			const sum = Object.values(CATEGORY_DEFAULTS).reduce((a, b) => a + b, 0);

// AFTER:
			const sum = Object.values(CATEGORY_DISPLAY_WEIGHTS).reduce((a, b) => a + b, 0);
```

**Step 3: Run tests**

Run: `npm test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/lib/scoring.ts test/scoring.spec.ts
git commit -m "refactor: rename CATEGORY_DEFAULTS to CATEGORY_DISPLAY_WEIGHTS for clarity"
```

---

### Task 7: Expand `explain_finding` status enum (Fix 7)

**Files:**
- Modify: `src/handlers/tool-schemas.ts`

**Step 1: Update the `explain_finding` schema**

In `src/handlers/tool-schemas.ts`, change the `status` property in the `explain_finding` tool (lines 113-116):

```typescript
// BEFORE:
			status: {
				type: 'string',
				enum: ['pass', 'fail', 'warning'],
				description: 'The check status',
			},

// AFTER:
			status: {
				type: 'string',
				enum: ['pass', 'fail', 'warning', 'critical', 'high', 'medium', 'low', 'info'],
				description: 'The check status or finding severity (e.g., pass, fail, warning, critical, high, medium, low, info)',
			},
```

**Step 2: Run tests**

Run: `npm test`
Expected: All tests pass (no test asserts exact enum values)

**Step 3: Commit**

```bash
git add src/handlers/tool-schemas.ts
git commit -m "feat: expand explain_finding status enum to include all severity levels"
```

---

### Task 8: Add HSTS and MX explanation entries (Fix 8)

**Files:**
- Modify: `src/tools/explain-finding.ts`

**Step 1: Add new entries to the `EXPLANATIONS` object**

In `src/tools/explain-finding.ts`, add the following entries after the existing `SSL_WARNING` entry (after line 150) and before `MTA_STS_PASS`:

```typescript
	SSL_MEDIUM: {
		title: 'HSTS or Redirect Issues',
		severity: 'medium',
		explanation:
			'HTTPS is available but the domain is missing HSTS (Strict-Transport-Security) headers or does not redirect HTTP to HTTPS. Without HSTS, browsers may still attempt insecure connections.',
		recommendation:
			'Add a Strict-Transport-Security header with max-age of at least 1 year (31536000). Configure your web server to redirect all HTTP requests to HTTPS.',
		references: ['https://https.cio.gov/hsts/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
	},
	SSL_LOW: {
		title: 'HSTS Configuration Suboptimal',
		severity: 'low',
		explanation:
			'HSTS is configured but could be improved. Common issues include a short max-age value or missing includeSubDomains directive.',
		recommendation:
			'Set max-age to at least 31536000 (1 year) and include the includeSubDomains directive. Consider adding your domain to the HSTS preload list.',
		references: [
			'https://hstspreload.org/',
			'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
		],
	},
```

Then add MX entries after the existing `MX_WARNING` entry (after line 236, before the closing `};`):

```typescript
	MX_INFO: {
		title: 'MX Records Present',
		severity: 'info',
		explanation: 'Mail exchange records are properly configured for this domain.',
		recommendation: 'No action required. Ensure backup MX records exist for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_LOW: {
		title: 'MX Configuration Could Be Improved',
		severity: 'low',
		explanation:
			'MX records are present but the configuration has minor issues such as missing backup MX records or duplicate priorities.',
		recommendation: 'Add at least one backup MX record with a different priority for redundancy.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_HIGH: {
		title: 'MX Configuration Error',
		severity: 'high',
		explanation:
			'MX records have a configuration error such as pointing to an IP address instead of a hostname, which violates RFC 5321.',
		recommendation:
			'Update MX records to point to valid hostnames, not IP addresses. Ensure all MX targets resolve to valid A/AAAA records.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321'],
	},
	MX_MEDIUM: {
		title: 'No MX Records Found',
		severity: 'medium',
		explanation:
			'No MX records are present for this domain. Email delivery will fall back to A record delivery or fail entirely.',
		recommendation:
			'If this domain should receive email, add MX records. If not, publish a null MX record per RFC 7505 to explicitly declare that.',
		references: ['https://datatracker.ietf.org/doc/html/rfc5321', 'https://datatracker.ietf.org/doc/html/rfc7505'],
	},
```

**Step 2: Run tests**

Run: `npm test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add src/tools/explain-finding.ts
git commit -m "feat: add SSL and MX explanation entries for explain_finding"
```

---

### Task 9: Bump version and update CHANGELOG (Final Steps)

**Files:**
- Modify: `package.json`
- Modify: `src/index.ts`
- Modify: `CHANGELOG.md`

**Step 1: Bump version in `package.json`**

Change line 3:
```json
// BEFORE:
	"version": "1.0.1",
// AFTER:
	"version": "1.0.2",
```

**Step 2: Bump `SERVER_VERSION` in `src/index.ts`**

Change line 27:
```typescript
// BEFORE:
const SERVER_VERSION = '1.0.1';
// AFTER:
const SERVER_VERSION = '1.0.2';
```

**Step 3: Add `[1.0.2]` entry to `CHANGELOG.md`**

Insert after line 6 (after the heading/format lines, before `## [1.0.0]`):

```markdown
## [1.0.2] - 2026-03-04

### Removed

- `upgrade_cta` from scan output — conversion hook belongs in README, not tool output

### Added

- HSTS header validation and HTTP→HTTPS redirect check in `check_ssl`
- Null MX (RFC 7505), IP address detection, redundancy check in `check_mx`
- SSL and MX explanation entries for `explain_finding`

### Changed

- `explain_finding` status enum expanded to include all severity levels (critical, high, medium, low, info)
- "No MX records found" severity from `high` to `medium`
- `CATEGORY_DEFAULTS` renamed to `CATEGORY_DISPLAY_WEIGHTS` for clarity

### Fixed

- CHANGELOG rate limit typo (50 → 100 req/hr)
- Static resources updated to reflect 10 checks (was "8 category checks")

```

**Step 4: Run full test suite and typecheck**

Run: `npm test && npm run typecheck`
Expected: All tests pass, no TypeScript errors

**Step 5: Commit**

```bash
git add package.json src/index.ts CHANGELOG.md
git commit -m "chore: bump version to 1.0.2 and update CHANGELOG"
```
