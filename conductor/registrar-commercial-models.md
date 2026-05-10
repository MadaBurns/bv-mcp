# Project Plan: Registrar Commercial & Implementation Models

## Background & Motivation
With the successful rollout of the Multi-Tenant Orchestrator (Phases 1-6) and the capacity to handle 2.5M+ domains, Blackveil DNS is positioned to partner with large enterprise registrars. These registrars manage vast domain portfolios but often lack advanced, scalable DNS and email security analytics. To effectively monetize this capability, we need structured implementation and revenue generation models that align with the business goals of enterprise registrars while driving significant recurring revenue for Blackveil.

## Scope & Impact
This design document defines three Revenue Generation Models and three Implementation Strategies. This will serve as the commercial framework for pitching to partners like "tenant-example", providing clear go-to-market strategies and technical integration paths.

## Proposed Solution: Revenue Generation Models

### 1. Wholesale / Capacity Reservation
*   **Description:** The registrar pre-purchases a dedicated block of scan capacity (e.g., 2.5M domains/day) and a fixed number of monthly Brand Discovery runs.
*   **Pros:** Predictable, high ARR for Blackveil. Simple billing. The registrar retains full control over their markup and end-customer pricing.
*   **Cons:** High upfront commitment may increase the sales cycle duration.
*   **Implementation Fit:** Best paired with the Headless API model.

### 2. Retail Revenue-Share (Freemium Upsell)
*   **Description:** Blackveil provides basic security scoring (e.g., the Entry/Assessment chapters) for free across the registrar's entire portfolio. The registrar upsells "Advanced Security Monitoring" or "Deep Brand Discovery" to their customers. Revenue is split (e.g., 70/30) between Blackveil and the registrar.
*   **Pros:** Extremely low barrier to entry. Drives massive volume and brand awareness. Highly scalable upside.
*   **Cons:** Revenue is less predictable and depends on the registrar's ability to upsell.
*   **Implementation Fit:** Best paired with the Embeddable UI or Managed Portal.

### 3. Usage-Based (Pay-As-You-Go)
*   **Description:** The registrar is billed based purely on API consumption (e.g., $X per 10,000 scans, $Y per Discovery run). 
*   **Pros:** Zero risk for the registrar, excellent for pilot phases or on-demand audit services.
*   **Cons:** Revenue can be volatile.
*   **Implementation Fit:** Works with any implementation, often used as a stepping stone to Wholesale.

## Proposed Solution: Implementation Models

### 1. API Integration (Headless)
*   **Description:** The registrar consumes the `POST /internal/tenants/*` (portfolio, scan, discover, report) endpoints directly, building their own UI within their existing control panel.
*   **Impact:** Highest integration effort for the registrar, but offers the most seamless experience for their end-users. Uses the existing Service Binding infrastructure.

### 2. White-Label / Embeddable UI
*   **Description:** Blackveil provides pre-built, customizable UI components (e.g., the React-based `ProgressiveResults` scanner) that the registrar can drop into their dashboard via iframe or NPM package.
*   **Impact:** Medium integration effort. Rapid time to market while maintaining the registrar's branding.

### 3. Managed Portal
*   **Description:** Blackveil hosts a dedicated, co-branded instance of the `bv-web` dashboard specifically for the registrar's Managed Service Providers (MSPs) or account managers to use on behalf of their clients.
*   **Impact:** Zero integration effort for the registrar's engineering team. Ideal for consultative selling and M&A discovery audits.

## Alternatives Considered
*   **Per-Domain Licensing:** Charging a flat annual fee per domain monitored. *Rejected* as it doesn't scale well with massive 2.5M+ portfolios where many domains are parked or inactive. Wholesale capacity or Rev-Share is more attractive to the registrar.

## Phased Implementation Plan

1.  **Phase 1: Pitch & Pilot (Weeks 1-2)**
    *   Present this commercial framework to the target registrar.
    *   Initiate a pilot using the **Usage-Based + Managed Portal** models to demonstrate value (e.g., a one-shot deep audit on a subset of 10,000 domains).
2.  **Phase 2: API Integration (Weeks 3-6)**
    *   Registrar engineering integrates the **Headless API**.
    *   Transition billing to a **Wholesale Capacity** contract.
3.  **Phase 3: Rev-Share Rollout (Weeks 7+)**
    *   Launch the basic security score across the registrar's entire portfolio.
    *   Activate the **Retail Revenue-Share** mechanism for premium upgrades.

## Verification
*   **Commercial:** Sign a pilot agreement with one enterprise registrar within 30 days.
*   **Technical:** Ensure the `bv-mcp` infrastructure handles the pilot load without breaching the agreed SLAs (verified by the new Hammer Chaos Suite).

## Migration & Rollback Strategies
*   If the Revenue-Share model underperforms, the contract can gracefully degrade to a Usage-Based model.
*   The API endpoints are strictly versioned, ensuring that any breaking changes to the scoring algorithm (e.g., the Jan 2026 AI-Resilience Gold Standard) do not impact the registrar's integration without prior notification.