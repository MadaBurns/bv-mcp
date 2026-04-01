# @blackveil/dns-checks

DNS and email security check implementations for [BlackVeil Security](https://blackveilsecurity.com).

> **License:** [BSL 1.1](./LICENSE) — Copyright (c) 2023-2026 BlackVeil Security Ltd.

## Installation

```bash
npm install @blackveil/dns-checks
```

## Usage

Every check takes a `queryDNS` function as its second argument (dependency injection):

```typescript
import { checkSPF } from '@blackveil/dns-checks';

const result = await checkSPF('example.com', async (domain, type, opts) => {
  // Your DNS resolver implementation
  return ['v=spf1 include:_spf.google.com ~all'];
});

console.log(result.score); // 0-100
console.log(result.findings); // Array of findings
```

## Scoring

```typescript
import { computeScanScore, scoreToGrade } from '@blackveil/dns-checks/scoring';

const score = computeScanScore(checkResults);
const grade = scoreToGrade(score.overall); // A+, A, B+, etc.
```

## Available Checks

| Check | Function | Standard |
|-------|----------|----------|
| SPF | `checkSPF` | RFC 7208 |
| DMARC | `checkDMARC` | RFC 7489 |
| DKIM | `checkDKIM` | RFC 6376 |
| DNSSEC | `checkDNSSEC` | RFC 4033 |
| SSL/TLS | `checkSSL` | — |
| MTA-STS | `checkMTASTS` | RFC 8461 |
| TLSRPT | `checkTLSRPT` | RFC 8460 |
| MX | `checkMX` | RFC 5321 |
| CAA | `checkCAA` | RFC 8659 |
| BIMI | `checkBIMI` | Draft |
| NS | `checkNS` | RFC 1035 |
| DANE Email | `checkDANE` | RFC 7672 |
| DANE HTTPS | `checkDANEHTTPS` | RFC 6698 |
| SVCB/HTTPS | `checkSVCBHTTPS` | RFC 9460 |
| Subdomain Takeover | `checkSubdomainTakeover` | — |
| HTTP Security | `checkHTTPSecurity` | — |

## License

Business Source License 1.1 (BSL 1.1). See [LICENSE](./LICENSE).
