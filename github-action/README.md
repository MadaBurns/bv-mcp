# Blackveil DNS Security Scanner — GitHub Action

Scan your domain's DNS and email security configuration in CI/CD. Powered by the [Blackveil DNS MCP server](https://github.com/MadaBurns/bv-mcp).

Runs a full DNS security audit (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, MX, CAA, BIMI, TLS-RPT, NS, subdomain takeover) and enforces a minimum grade threshold. Fails the workflow if the domain's security posture is below the required grade.

## Quick Start

```yaml
name: DNS Security Check
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * 1" # Weekly Monday 6am

jobs:
  dns-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan DNS security
        uses: MadaBurns/blackveil-dns-action@v1
        id: scan
        with:
          domain: example.com
          minimum-grade: C

      - name: Print results
        if: always()
        run: |
          echo "Score: ${{ steps.scan.outputs.score }}"
          echo "Grade: ${{ steps.scan.outputs.grade }}"
          echo "Maturity: ${{ steps.scan.outputs.maturity }}"
          echo "Passed: ${{ steps.scan.outputs.passed }}"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `domain` | Yes | — | Domain to scan (e.g. `example.com`) |
| `minimum-grade` | No | `C` | Minimum passing grade. One of: `A+`, `A`, `B+`, `B`, `C+`, `C`, `D+`, `D`, `E`, `F` |
| `endpoint` | No | `https://dns-mcp.blackveilsecurity.com/mcp` | MCP endpoint URL |

## Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `score` | Numeric score (0-100) | `82` |
| `grade` | Letter grade | `B+` |
| `maturity` | Email security maturity stage | `Enforcing` |
| `passed` | Whether grade meets threshold | `true` |

## Grade Scale

| Grade | Score Range |
|-------|-------------|
| A+ | 90-100 |
| A | 85-89 |
| B+ | 80-84 |
| B | 75-79 |
| C+ | 70-74 |
| C | 65-69 |
| D+ | 60-64 |
| D | 55-59 |
| E | 50-54 |
| F | 0-49 |

## Examples

### Enforce Strict Grade on Production Domains

```yaml
- name: Scan production domain
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: mycompany.com
    minimum-grade: B+
```

### Scan Multiple Domains

```yaml
jobs:
  dns-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        domain: [mycompany.com, mail.mycompany.com, api.mycompany.com]
      fail-fast: false
    steps:
      - name: Scan ${{ matrix.domain }}
        uses: MadaBurns/blackveil-dns-action@v1
        with:
          domain: ${{ matrix.domain }}
          minimum-grade: C
```

### Use Outputs in Downstream Steps

```yaml
- name: Scan DNS
  id: dns
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: example.com
    minimum-grade: F  # Don't fail — we check manually below

- name: Warn on low grade
  if: steps.dns.outputs.passed == 'false'
  run: echo "::warning::DNS grade ${{ steps.dns.outputs.grade }} is below target"

- name: Block deploy on critical issues
  if: steps.dns.outputs.grade == 'F'
  run: |
    echo "::error::DNS security grade F — blocking deployment"
    exit 1
```

### Scheduled Monitoring with Slack Notification

```yaml
name: Weekly DNS Audit
on:
  schedule:
    - cron: "0 9 * * 1"

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Scan DNS
        id: scan
        uses: MadaBurns/blackveil-dns-action@v1
        continue-on-error: true
        with:
          domain: mycompany.com
          minimum-grade: B

      - name: Notify on failure
        if: steps.scan.outputs.passed == 'false'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "DNS Security Alert: ${{ steps.scan.outputs.grade }} (${{ steps.scan.outputs.score }}/100) for mycompany.com"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Branch Protection (Require DNS Grade)

To enforce DNS security as a required status check:

1. Add the scan job to your PR workflow:

```yaml
name: PR Checks
on: pull_request

jobs:
  dns-security:
    runs-on: ubuntu-latest
    steps:
      - name: DNS security gate
        uses: MadaBurns/blackveil-dns-action@v1
        with:
          domain: mycompany.com
          minimum-grade: C+
```

2. In your repository settings, go to **Settings > Branches > Branch protection rules**.
3. Enable **Require status checks to pass before merging**.
4. Add `dns-security` as a required check.

## Job Summary

The action writes a detailed summary to the GitHub Actions job summary, including:

- Overall score, grade, and maturity stage
- Category-by-category score breakdown table
- Top findings with severity indicators

The summary is visible in the Actions run UI under the **Summary** tab.

## How It Works

1. Initializes an MCP session with the Blackveil DNS server
2. Calls the `scan_domain` tool via JSON-RPC 2.0
3. Parses the scan report for score, grade, maturity, and findings
4. Writes outputs and a Markdown job summary
5. Exits with code 1 if the grade is below the minimum threshold

No API key is required — the public endpoint is free to use with rate limiting (30 req/min, 200 req/hr).

## License

MIT
