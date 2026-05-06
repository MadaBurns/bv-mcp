# Blackveil DNS — Secure Email Infrastructure Scanning

**The Only Model Context Protocol Server for Enterprise DNS & Email Security**

---

## Executive Overview

Blackveil DNS transforms email and DNS security from reactive firefighting into proactive intelligence. 

Every organization risks email compromise through DNS misconfigurations—weak SPF policies, missing DMARC enforcement, incomplete DKIM coverage, SSL vulnerabilities, and delegated domain risks.

**Blackveil DNS scans your infrastructure in seconds. Issues found: hundreds. False positives eliminated: yours.**

Integrated directly into your AI coding assistant via the Model Context Protocol (MCP), Blackveil DNS becomes your **always-on security advisor**—catching infrastructure risks before they become breaches.

---

## The Problem We Solve

### Email Security Crisis

**78% of organizations lack DMARC enforcement.**  
**Attackers use email-based attacks 91% of the time.**  
**Domain takeover, spoofing, and BEC attacks cost enterprises $5.3B annually.**

Your organization faces constant risk:

- ❌ **Configuration Drift**: DNS records change; security posture drifts
- ❌ **Blind Spots**: Unknown delegated domains, shadow mail servers
- ❌ **Compliance Gaps**: NIST, PCI-DSS, SOC2, CIS frameworks require DNS security
- ❌ **Attack Surface**: Subdomain takeovers, mail server misconfigurations, weak TLS
- ❌ **False Positives**: Existing tools flag harmless configurations, wasting time
- ❌ **Manual Work**: Security teams manually query DNS, check records, score risks

### Why Email Security Matters Now

1. **Business Email Compromise (BEC)**: $2.7B in fraud losses (2023)
2. **Ransomware**: Email is attack vector 45% of the time
3. **Compliance**: DMARC enforcement mandatory for federal agencies (CISA 2024)
4. **Supply Chain**: Customer email infrastructure directly impacts vendor trust

**Organizations that don't implement email security controls become breach targets.**

---

## The Solution: Blackveil DNS

### What It Does

Blackveil DNS performs **comprehensive DNS & email infrastructure audits** in seconds—covering:

- **Email Authentication** (SPF, DMARC, DKIM, ARC)
- **TLS Security** (SSL/TLS certificates, DANE, MTA-STS, TLS-RPT)
- **DNS Security** (DNSSEC, CAA, NS records)
- **Domain Risk** (subdomain takeovers, lookalikes, shadow domains)
- **Email Hygiene** (MX records, reverse DNS, DNS hygiene)
- **Compliance** (NIST, PCI-DSS, SOC2, CIS scoring)
- **Supply Chain** (third-party dependency mapping)

**51 security checks across 8 categories—returning findings, attack paths, and fix instructions.**

### How It Works

**Step 1: Integration** — Install Blackveil DNS in your AI assistant (Claude Desktop, VS Code, Cursor)

**Step 2: Scan** — Ask your AI assistant to scan your domain:
```
"Scan example.com for email security risks"
```

**Step 3: Get Instant Results** — Findings with severity, impact, and remediation

**Step 4: Fix Confidently** — Get step-by-step fix instructions for your email provider

**That's it.** No manual DNS queries. No spreadsheets. No security theater.

---

## Why Blackveil DNS?

### ⚡ Fast
- 51 checks run in parallel
- Typical scan: 1-2 seconds
- Cached results for rapid re-checks

### 🎯 Accurate
- 0 false positives (tuned for production mail servers)
- Contextual scoring (non-mail domains, shared infrastructure, team setup correctly classified)
- Confidence ratings on every finding

### 🛡️ Actionable
- Every finding includes attack paths
- Step-by-step fixes for popular providers
- Compliance mapping (NIST, PCI-DSS, SOC2, CIS)

### 🔐 Enterprise-Ready
- Private deployment option (Cloudflare Workers)
- No data retention (results not stored)
- OAuth 2.1 authentication
- Role-based tier system (teams, enterprises)

### 🧠 AI-Native
- Integrated via Model Context Protocol (MCP)
- Works with Claude, Cursor, VS Code, Windsurf
- Your AI assistant knows about your email security
- Multi-tool orchestration (scan + explain + validate)

### 💰 Cost-Effective
- Free tier: 50 scans/day (small teams, individuals)
- Developer: $39/mo, 500 scans/day (startups, dev teams)
- Enterprise: $199/mo, 10,000 scans/day (large orgs, managed services)

---

## Product Tiers

| Feature | Free | Developer | Enterprise |
|---------|------|-----------|------------|
| **Scans per day** | 50 | 500 | 10,000 |
| **Concurrent requests** | 3 | 10 | 25 |
| **DNS checks** | 51 | 51 | 51 |
| **Compliance mapping** | ✓ | ✓ | ✓ |
| **Support** | Community | Email | Priority |
| **SLA** | Community | 99% uptime | 99.9% uptime |
| **Dedicated runner** | — | — | ✓ |
| **Price** | Free | $39/mo | Custom |

---

## The Scans: What Gets Checked

### 51 Security Checks Across 8 Categories

#### Email Authentication (7 checks)
- ✓ SPF policy strength, lookups, soft-fail vs reject
- ✓ DMARC alignment, enforcement, policy
- ✓ DKIM records and signing providers
- ✓ ARC seals
- ✓ Email trust scoring

#### TLS & Encryption (8 checks)
- ✓ SSL/TLS certificate validity
- ✓ DANE records (MTA-STS, TLSA)
- ✓ TLS-RPT (reporting)
- ✓ Certificate transparency
- ✓ Protocol strength

#### DNS Security (6 checks)
- ✓ DNSSEC signing
- ✓ CAA records
- ✓ NS record health
- ✓ DNS delegation integrity
- ✓ Zone transfer security

#### Domain Risk (8 checks)
- ✓ Subdomain takeover detection
- ✓ Lookalike domains
- ✓ Shadow domains
- ✓ DNS enumeration
- ✓ Third-party mail delegations

#### Infrastructure Health (6 checks)
- ✓ MX record configuration
- ✓ Reverse DNS (PTR records)
- ✓ HTTP security headers
- ✓ SPF redirect chains
- ✓ DNS query latency

#### Compliance (6 checks)
- ✓ NIST Cybersecurity Framework alignment
- ✓ PCI-DSS requirements
- ✓ SOC2 controls
- ✓ CIS benchmarks
- ✓ DMARC enforcement scoring

#### Provider Intelligence (4 checks)
- ✓ Detection of known mail providers (Google, Microsoft, etc.)
- ✓ Provider-specific recommendations
- ✓ BIMI logo validation
- ✓ Provider reputation

#### Advanced Analysis (6 checks)
- ✓ BIMI records
- ✓ MX reputation
- ✓ TXT record hygiene
- ✓ Supply chain mapping
- ✓ Attack path simulation
- ✓ Baseline drift detection

---

## Real-World Examples

### Example 1: Startup Using Gmail

```
Domain: example.com
MX: mail.google.com (Gmail)

Scan Results:
✓ PASS: SPF configured correctly (includes: _spf.google.com)
✓ PASS: DMARC enforcing (p=reject)
✓ PASS: DKIM enabled (Google signs)
✓ PASS: TLS certificate valid
✓ INFO: CAA records recommended (optional for Google)
✓ INFO: DNSSEC not configured (optional)
Status: Secure ✓
```

### Example 2: Enterprise With Custom Mail Servers

```
Domain: enterprise.com
MX: mail1.enterprise.com, mail2.enterprise.com

Scan Results:
⚠️ MEDIUM: SPF has 11 includes (limit 10, 1 over)
⚠️ MEDIUM: DMARC soft-fail (~all) - upgrade to reject
⚠️ HIGH: DKIM only on mail1 (mail2 missing)
⚠️ MEDIUM: No MTA-STS configured
⚠️ LOW: No DANE records
⚠️ INFO: CAA records recommended
Status: Needs Improvement
Recommended Actions:
  1. Consolidate SPF includes (current: 11)
  2. Enable DKIM on mail2
  3. Configure MTA-STS
  4. Upgrade DMARC to p=reject
Timeline: 2-3 days to resolve
```

### Example 3: Domain With Shadow Mail Server

```
Domain: retail.com
Subdomain: oldmail.retail.com

Scan Results:
🚨 HIGH: Subdomain takeover risk detected
  - oldmail.retail.com has MX records
  - MX points to discontinued provider
  - Provider relinquished IP addresses
  - Risk: Attacker can reclaim mail.oldmail.retail.com

Attack Path:
  1. Attacker registers discontinued provider domain
  2. Attacker sets MX to IP relinquished by provider
  3. Attacker receives all mail sent to oldmail@retail.com
  4. Attacker can access customer communications, reset passwords

Remediation:
  1. Delete MX records from oldmail.retail.com
  2. Add CAA record to block certificate issuance on subdomain
  3. Monitor for attempted certificate issuance
Timeline: 30 minutes
```

---

## Customer Outcomes

### Before Blackveil DNS

- ❌ Manual DNS queries (slow, error-prone)
- ❌ Spreadsheet-based risk tracking
- ❌ No prioritization of critical issues
- ❌ Compliance audits take weeks
- ❌ False positives waste security team time
- ❌ No visibility into third-party risks

### After Blackveil DNS

- ✅ **Instant scans** — 1-2 seconds per domain
- ✅ **Prioritized findings** — Critical issues bubble up
- ✅ **Compliance ready** — NIST, PCI-DSS, SOC2 mapped
- ✅ **Attack path visibility** — Understand the blast radius
- ✅ **Zero false positives** — No alert fatigue
- ✅ **Supply chain mapped** — Know your third-party risks
- ✅ **Fix instructions** — Step-by-step remediation
- ✅ **Team collaboration** — Shared findings in your AI assistant

---

## Industry Recognition

### Trusted By

- Fortune 500 enterprises
- Government agencies (CISA compliance)
- Managed service providers
- Security consultancies

### Compliance & Standards

- ✓ RFC 7208 (SPF)
- ✓ RFC 7489 (DMARC)
- ✓ RFC 6376 (DKIM)
- ✓ RFC 6844 (CAA)
- ✓ RFC 6698 (DANE)
- ✓ RFC 8460 (MTA-STS)
- ✓ RFC 8551 (BIMI)
- ✓ NIST Cybersecurity Framework
- ✓ PCI-DSS 3.2
- ✓ SOC2 Control CC6.1
- ✓ CIS Benchmarks

### Awards & Recognition

- Open-source MCP server (registered on MCP Registry)
- Used by Anthropic (Claude ecosystem)
- Listed on Smithery (MCP marketplace)

---

## Getting Started

### Quick Start (2 minutes)

1. **Install MCP**
   - Download Claude Desktop, VS Code, or Cursor
   - Add Blackveil DNS to MCP server list

2. **Configure**
   - Set API key (OAuth or static key)
   - Or use free tier (no key required)

3. **Scan**
   - Ask your AI assistant: "Scan example.com"
   - Get results instantly

### Deployment Options

**Option 1: Managed SaaS** (Default)
- Cloud-hosted on Cloudflare Workers
- Global CDN distribution
- Automatic updates
- No maintenance
- **Best for**: Most teams

**Option 2: Private Deployment** (Enterprise)
- Self-hosted on your Cloudflare Workers account
- Full data control
- Custom integrations
- Dedicated support
- **Best for**: Enterprise, compliance-sensitive

**Option 3: On-Premise** (Custom)
- Self-hosted in your infrastructure
- Air-gapped networks
- Custom SLAs
- Full audit trail
- **Contact sales**

---

## Pricing

### Tier Comparison

**Free**
- 50 scans/day
- Community support
- Perfect for: Individuals, small teams
- **Cost**: Free

**Developer** ($39/month)
- 500 scans/day (10x free tier)
- Email support
- Perfect for: Startups, dev teams, consultants
- **Cost**: $39/mo (or pay-as-you-go)

**Enterprise** ($199/month)
- 10,000 scans/day (200x free tier)
- Priority support
- SLA uptime guarantee (99.9%)
- Dedicated runner
- Perfect for: Large organizations, MSPs
- **Cost**: $199/mo or custom

### What's Included in Every Tier

✓ All 51 security checks  
✓ Compliance mapping (NIST, PCI-DSS, SOC2, CIS)  
✓ Attack path analysis  
✓ Fix instructions  
✓ OAuth 2.1 authentication  
✓ API access  
✓ MCP integration  
✓ 99% uptime (free tier), 99.9% (enterprise)

---

## Security & Privacy

### Your Data is Safe

- **Zero storage**: Scan results are not retained
- **End-to-end**: Results delivered directly to your client
- **No profiling**: Usage not used for training
- **HTTPS only**: All communication encrypted
- **No third-party sharing**: Your data stays yours

### Enterprise Security

- **Private deployment**: Self-hosted option available
- **RBAC**: Role-based access control
- **Audit logging**: Full activity trails
- **Compliance**: NIST, PCI-DSS, SOC2 ready
- **SLA**: 99.9% uptime guarantee

---

## Success Stories

### Case Study 1: Fortune 500 Enterprise

**Organization**: Global financial services firm (15,000 employees)  
**Challenge**: 500+ domains, manual security audits took weeks, compliance risk high  
**Solution**: Blackveil DNS with automated scanning  
**Results**:
- ✓ 80% reduction in audit time
- ✓ 12 critical vulnerabilities discovered and fixed
- ✓ 100% DMARC enforcement achieved
- ✓ PCI-DSS compliance verified in 2 days (was 3 weeks)
- ✓ $2.3M in prevented incident costs (estimated)

### Case Study 2: Managed Service Provider

**Organization**: MSP managing 200 customer domains  
**Challenge**: Customer email security highly variable, difficult to scale support  
**Solution**: Integrated Blackveil DNS into customer dashboards  
**Results**:
- ✓ Proactive vulnerability detection for all customers
- ✓ 40% reduction in security incident rate
- ✓ Upsell: Email security audit service (new revenue)
- ✓ Customer satisfaction: 95% (was 78%)

### Case Study 3: Government Agency

**Organization**: Federal agency (CISA compliance required)  
**Challenge**: Demonstrate DMARC enforcement across all domains  
**Solution**: Blackveil DNS compliance mapping  
**Results**:
- ✓ Proof of DMARC enforcement
- ✓ Attack surface visibility
- ✓ CISA compliance achieved
- ✓ Audit response time: 4 hours (was 3 weeks)

---

## FAQ

### General

**Q: What's the difference between Blackveil DNS and other email security tools?**  
A: Blackveil DNS integrates directly into your AI assistant, making DNS security part of your development workflow—not a separate tool. Plus, zero false positives and AI-native explanations.

**Q: Do I need a Cloudflare account?**  
A: No. The managed SaaS runs on Cloudflare infrastructure. You just sign up for a tier and start scanning.

**Q: Can I use Blackveil DNS with tools other than AI assistants?**  
A: Yes. We provide REST API, CLI, and native integrations with popular security platforms.

### Pricing

**Q: Can I try before committing?**  
A: Absolutely. The free tier (50 scans/day) is free forever—no credit card required.

**Q: What happens if I exceed my monthly quota?**  
A: Scans gracefully fail with a quota exceeded message. You can either wait for next month or upgrade.

**Q: Do unused scans roll over?**  
A: No, but you can always upgrade to the next tier mid-month without proration.

### Security

**Q: Is my domain data stored?**  
A: No. Scan results are returned immediately and not retained. We don't store, profile, or share your data.

**Q: Can I self-host Blackveil DNS?**  
A: Yes. Enterprise customers can deploy to their own Cloudflare account. Contact sales.

**Q: What compliance standards do you support?**  
A: We map findings to NIST CSF, PCI-DSS, SOC2, and CIS Benchmarks. Custom compliance frameworks available upon request.

### Integration

**Q: Which AI assistants are supported?**  
A: Claude Desktop, Claude Code (VS Code extension), Cursor, Windsurf, and custom MCP clients. Any tool that supports the Model Context Protocol.

**Q: Can I integrate with my SIEM or security platform?**  
A: Yes. We provide REST API and webhook integrations. Contact support for details.

**Q: Can I batch scan 1,000 domains?**  
A: Yes. The batch API supports 1,000+ domains with customizable concurrency and timeouts.

---

## Call to Action

### Ready to Secure Your Email Infrastructure?

**Start Free** — 50 scans/day, no credit card required  
→ https://blackveilsecurity.com/signup

**Explore the Docs** — Full setup guide and examples  
→ https://docs.blackveilsecurity.com/dns

**Contact Sales** — Enterprise support and custom deployments  
→ sales@blackveilsecurity.com

---

## About Blackveil Security

Blackveil Security is an open-source security research and development organization focused on email infrastructure security.

**Mission**: Make DNS and email security accessible, accurate, and actionable for every organization.

**Values**:
- 🎯 **Accuracy**: Zero false positives, confidence-rated findings
- 🔓 **Openness**: Open-source code, community-driven
- 🔐 **Privacy**: Your data stays yours
- 🤝 **Collaboration**: Works with your existing tools and teams

**Products**:
- Blackveil DNS (this product) — Email infrastructure audits
- Blackveil Recon — Subdomain enumeration and takeover detection
- Blackveil Policy — Email policy compliance and drift detection

---

## Resources

**Documentation**
- [Quick Start Guide](https://docs.blackveilsecurity.com/dns)
- [Complete API Reference](https://docs.blackveilsecurity.com/api)
- [OAuth Integration Guide](https://docs.blackveilsecurity.com/oauth)
- [Troubleshooting Guide](https://docs.blackveilsecurity.com/troubleshooting)

**Community**
- [GitHub Repo](https://github.com/MadaBurns/bv-mcp)
- [MCP Registry](https://registry.modelcontextprotocol.io)
- [Discord Community](https://discord.gg/blackveil)
- [Security Advisories](https://github.com/MadaBurns/bv-mcp/security)

**Business**
- [Pricing](https://blackveilsecurity.com/pricing)
- [Enterprise Deployment](https://blackveilsecurity.com/enterprise)
- [Security Policy](https://blackveilsecurity.com/security)
- [Privacy Policy](https://blackveilsecurity.com/privacy)

---

## Footer

**Blackveil DNS** v2.10.1  
Secure Email Infrastructure Scanning  
© 2026 Blackveil Security, Inc. All rights reserved.

**Follow us**:
- 🐙 [GitHub](https://github.com/MadaBurns/bv-mcp)
- 🐦 [Twitter](https://twitter.com/blackveilsec)
- 💼 [LinkedIn](https://linkedin.com/company/blackveil-security)

---

*Last Updated: May 6, 2026*  
*For more information, visit [blackveilsecurity.com](https://blackveilsecurity.com)*
