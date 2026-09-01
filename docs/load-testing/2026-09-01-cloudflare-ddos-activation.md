# Cloudflare DDoS activation — 2026-09-01

## Summary

A locally generated production edge-capacity test activated a Cloudflare DDoS rule. The event invalidated the suspected capacity boundary because Cloudflare mitigation, not demonstrated Worker saturation, constrained accepted traffic.

## Impact

- High-rate requests experienced failures, dial timeouts, and connection resets.
- Independent health monitoring triggered its stop behavior during one repetition.
- The test stopped after consecutive unstable stages.
- Post-test production health returned HTTP 200 with normal latency.
- Available evidence showed no corruption, cross-tenant leakage, queue corruption, or persistent ordinary-user degradation.

## Timeline

1. Edge stages from 10 through 800 RPS completed successfully once.
2. The 1,600-RPS stage crossed the failure threshold and aborted.
3. Refinement at 960 and 1,120 RPS also aborted.
4. Repetition at 800 RPS first succeeded, then encountered VU exhaustion, dropped iterations, dial timeouts, resets, and probe failure.
5. Cloudflare security telemetry confirmed DDoS-rule activation.
6. All load stopped; three recovery probes returned HTTP 200.

Security-event identifiers, source addresses, account identifiers, and raw Cloudflare exports belong only in the restricted evidence store.

## Root cause

The offered traffic was a uniform, single-source request stream against one edge endpoint. At the attempted rates, that pattern crossed Cloudflare's DDoS detection boundary. The test had not been coordinated with a Cloudflare-approved treatment for the test source.

This was a test-design and coordination failure, not evidence that DDoS protection malfunctioned.

## Contributing factors

- A single source concentrated traffic and resembled an attack pattern.
- The test attempted to infer global capacity from a workstation source path.
- The harness could not directly correlate failures with Cloudflare Security Events.
- The edge lane did not distinguish mitigation from generic transport or HTTP failure.
- An unrelated D1 control-plane error blocked deployment of the identity-bound authenticated lanes.

## Corrective actions

Before another production run:

- Obtain Cloudflare confirmation for planned rates and topology.
- Define approved generator addresses and the test window.
- Decide with Cloudflare whether identity-and-source-scoped treatment is supported. Never disable global DDoS protection.
- Use distributed dedicated runners and independent monitoring.
- Add Security Events correlation and transport/mitigation classification to the evidence workflow.
- Prove the global kill switch at every generator.
- Resolve the production D1 preflight failure before creating the temporary authenticated identity.

Until then:

- Do not run another production staircase from a workstation.
- Do not resume at 800 RPS or above.
- Keep production testing at smoke-test rates unless a new coordinated window is approved.
- Treat the 2026-09-01 figures as harness observations, not capacity commitments.

## Closure

The production-impacting event is closed when health, ordinary-user probes, security mitigations, and downstream queues are at baseline. Readiness for a future capacity test is a separate gate.
