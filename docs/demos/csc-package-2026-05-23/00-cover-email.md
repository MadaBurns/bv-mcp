# Cover Email — Vincent & Ihab (CSC DomainSec partnership)

**Suggested subject:** BlackVeil DNS — DomainSec complement: AI-vendor case study (3 attachments, 90-sec read up front)

**To:** Vincent — \<stakeholder-one@example.com\>; Ihab — \<stakeholder-two@example.com\>
**From:** Adam — contact@example.com
**Attachments:** `01-exec-summary.pdf` · `02-walkthrough.pdf` · `03-provenance.pdf`

---

Vincent / Ihab —

Following on from our conversation about where BlackVeil DNS fits next to CSC DomainSec, I ran the case study we discussed against three AI vendors — **OpenAI, Anthropic, x.ai** — and then validated the methodology against a broader **22-provider cohort (25 providers in total, including the three named cases)**. Everything was observed from public DNS, RDAP, WHOIS, and Certificate Transparency. Nothing privileged, nothing CSC-customer-specific. The capability comparison in the exec summary was also validated against your current product pages (DomainSec + Subdomain Monitoring) to make sure I wasn't strawmanning what CSC already covers.

**The 90-second read** (full version in `01-exec-summary.pdf`):

- **1 CRITICAL takeover candidate** on `cdn.openai.com` — Azure Front Door endpoint name is user-claimable and the provider returns `ResourceNotFound` on every probed path. This is the kind of finding that travels in customer conversations.
- **9 dangling endpoints on x.ai's model-serving zone** — all from a single AWS NLB deletion. One operational miss, nine orphaned production endpoints, including subdomain names that disclose an unannounced model (`grok-4-code-0630`) via public CT logs.
- **0 dangling across Anthropic's 129 subdomains** — and **21 of 25 cohort providers (84%) fully clean** across the expanded sweep (Anthropic, Cohere, Databricks, Glean, Stripe and 16 others, zero findings). The honest negative matters: it's evidence the tool isn't a noise-generator, and it's a defensible answer for an _"is our subdomain inventory under control?"_ customer ask.
- **All 3 brief-named registrars (GoDaddy, Network Solutions, Namecheap) surfaced** in the brand-coincidence sweep, plus 6 confirmed brand-owned apexes — 3 of those on third-party registrars (off the customer's managed portfolio).

**Where this fits the DomainSec value chain:** BlackVeil DNS is the technical surface CSC's portfolio-centric inventory doesn't enumerate today — _not_ a portfolio-management replacement. CT-log subdomain enumeration, dangling-DNS / dangling-CDN detection, off-portfolio brand discovery, and per-apex email-auth posture grading. The capability comparison sits on page 1 of the exec summary.

**Reproducibility:** every finding in the package is independently verifiable from public data. `03-provenance.pdf` has the full verification matrix and the `dig` / `curl` / `crt.sh` commands to re-derive each one. Full audit re-runs against the three primary apexes in ~90 seconds end-to-end.

**Next step (your call):** happy to walk the package live — 20 minutes, screen-share, in roughly the same order the walkthrough doc is structured (Anthropic-clean → OpenAI CRITICAL → x.ai cluster → grok-4-code disclosure → off-portfolio sprawl). Or if reading at your own pace works better, the docs stand alone. Either way, ping me with questions and I'll re-run anything you want to verify on the spot.

Talk soon,
Adam

---

_Adam — BlackVeil Security · contact@example.com_
_BlackVeil DNS · [dns-mcp.blackveilsecurity.com/mcp](https://dns-mcp.blackveilsecurity.com/mcp)_
