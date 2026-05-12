# Asset Discovery Integration & Documentation Update

## Objective
Implement live integration tests and a ground-truth corpus for the asset discovery tools (`discoverBrandDomains`, `discoverSubdomains`, `checkShadowDomains`), and update the architecture documentation to reflect the finalized v1 implementation.

## Key Files & Context
- `test/asset-discovery-integration.spec.ts` (New)
- `test/fixtures/asset-discovery-corpus.json` (New)
- `docs/tenant-Capacity-and-Discovery-Design.md` (Update)

## Implementation Steps
1. **Design Live Corpus & Ground Truth**:
   - Create `test/fixtures/asset-discovery-corpus.json`.
   - Define a live seed domain (e.g., `blackveilsecurity.com` or `example.com`).
   - Hardcode "ground truth" expectations: known minimum subdomains, known brand variants, and expected minimum shadow domains.
2. **Write Integration Test**:
   - Create `test/asset-discovery-integration.spec.ts`.
   - Import the actual unmocked MCP tools (`src/tools/discover-brand-domains`, `src/tools/discover-subdomains`, `src/tools/check-shadow-domains`).
   - Execute the tools against the live corpus domain, allowing real network calls to DNS and crt.sh.
   - Assert that the output `CheckResult`s contain the baseline findings specified in the ground truth corpus (e.g., using `expect.arrayContaining` to allow for live additions over time).
3. **Rewrite Architecture Documentation**:
   - Edit `docs/tenant-Capacity-and-Discovery-Design.md` (the file that superseded the internal discovery notes).
   - Rewrite Section 2 (`Registrar-discovery system design`).
   - Change the tone from "proposed build sequence" to "implemented system".
   - Document the newly added live integration test strategy and corpus mechanism.

## Verification & Testing
- Run the new integration test and ensure it passes against the live network.
- Ensure the updated design document accurately reflects the current state of the codebase.