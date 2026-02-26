# BLACKVEIL Scanner (npm package)

Core DNS/email security library for domain posture analysis, used by the BLACKVEIL Scanner MCP server.

## Installation

```bash
npm install blackveil-scanner
```

## Usage

```ts
import {
	scanDomain,
	checkSpf,
	checkDmarc,
	checkDkim,
	checkDnssec,
	checkSsl,
	checkMtaSts,
	checkNs,
	checkCaa,
	checkMx,
	explainFinding,
	validateDomain,
	sanitizeDomain,
	calculateScanScore,
	CATEGORY_WEIGHTS,
} from 'blackveil-scanner';

const domain = 'example.com';
const scan = await scanDomain(domain);
console.log(scan.results, scan.score);

const spf = await checkSpf(domain);
console.log(spf);

const explanation = explainFinding('SPF', 'fail', spf.findings[0]?.detail);
console.log(explanation);
```

## API Reference

- `scanDomain(domain: string): Promise<{ results: Record<string, CheckResult>, score: number }>` — Run all checks in parallel and return combined results and score.
- `checkSpf(domain: string): Promise<CheckResult>` — SPF record check
- `checkDmarc(domain: string): Promise<CheckResult>` — DMARC policy check
- `checkDkim(domain: string, selector?: string): Promise<CheckResult>` — DKIM selector/key check
- `checkDnssec(domain: string): Promise<CheckResult>` — DNSSEC validation
- `checkSsl(domain: string): Promise<CheckResult>` — SSL/TLS certificate check
- `checkMtaSts(domain: string): Promise<CheckResult>` — MTA-STS policy check
- `checkNs(domain: string): Promise<CheckResult>` — Name server configuration check
- `checkCaa(domain: string): Promise<CheckResult>` — CAA record check
- `checkMx(domain: string): Promise<CheckResult>` — MX record check
- `explainFinding(checkType: string, status: 'pass' | 'fail' | 'warning', details?: string): string` — Generate plain-language explanation
- `validateDomain(domain: string): { valid: boolean, error?: string }` — Validate domain input
- `sanitizeDomain(domain: string): string` — Sanitize domain input
- `calculateScanScore(results: Record<string, CheckResult>): number` — Compute overall scan score
- `CATEGORY_WEIGHTS: Record<CheckCategory, number>` — Scoring weights

## Features
- Strict domain validation
- SSRF protection
- Weighted scoring
- Modular check tools
- All checks return structured results
- Easy integration with Node.js, TypeScript, and browser environments

## License
MIT
