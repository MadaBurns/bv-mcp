# Global ceiling operator runbook

## Authority and stop rule

Production execution requires explicit approval for the test window and rate envelope. Any operator may stop the test. No operator may bypass a failed deployment, schema, security, or kill-switch gate merely to continue testing.

Never weaken account-wide DDoS protection. A security-rule treatment, when Cloudflare supports and approves it, must be limited to the temporary identity and exact generator addresses and removed immediately afterward.

## Preconditions

- The harness release is live and verified.
- Cloudflare policy and notification requirements are satisfied.
- Security Events and DDoS analytics are open on an independent monitor.
- Queue, Worker, service-binding, and cost telemetry are visible.
- `k6` is installed on every generator.
- The temporary key and allowlist are active; an unapproved address fails closed.
- The kill switch returns exactly `run`, and changing it stops every generator.
- `BV_LOAD_DOMAIN` is an approved BlackVeil-controlled domain for useful, heavy, or mixed lanes.

## Environment

Set secrets without printing them or placing them in shell history.

| Variable | Meaning |
| --- | --- |
| `BV_LOAD_BASE_URL` | Production or staging origin |
| `BV_LOAD_LANE` | `edge`, `protocol`, `useful`, `heavy`, or `mixed` |
| `BV_LOAD_TEST_KEY` | Temporary credential; required outside `edge` |
| `BV_LOAD_DOMAIN` | Approved controlled domain |
| `BV_LOAD_UNCACHED_SUFFIX` | Controlled suffix for uncached checks |
| `BV_LOAD_KILL_SWITCH_URL` | Endpoint whose body must be exactly `run` |
| `BV_LOAD_RATES` | Comma-separated staircase rates |
| `BV_LOAD_STAGE_DURATION` | Stage duration; production default `5m` |
| `BV_LOAD_RECOVERY_MS` | Recovery interval; production default `120000` |

## Validation

```bash
npm run audit:repo-safety
npm test -- test/tier-auth.spec.ts
k6 inspect scripts/load/global-ceiling.k6.js
```

Run a one-RPS staging smoke. Verify SSE parsing, JSON-RPC errors, `result.isError`, invalid schemas, analytics identity, independent probes, and kill-switch termination.

## Production execution

Start with one lane and one region:

```bash
BV_LOAD_LANE=edge \
BV_LOAD_RATES=10 \
BV_LOAD_STAGE_DURATION=5m \
BV_LOAD_RECOVERY_MS=120000 \
npm run load:global-ceiling:run
```

Authenticated lanes require the temporary key. Useful, heavy, and mixed lanes require `BV_LOAD_DOMAIN`. After baseline reconciliation, expand to the approved regional topology. The global controller stops every generator when any region or independent monitor crosses a stop condition.

## Stop conditions

Abort globally when any condition persists for 30 seconds:

- HTTP 5xx exceeds 1%.
- MCP semantic failures exceed 1%.
- Lightweight p95 exceeds two seconds.
- Full-scan p95 exceeds 30 seconds.
- The ordinary-user probe fails twice.
- Queue backlog exceeds its recovery threshold.
- Durable Object errors or upstream throttling materially increase.
- Cloudflare activates DDoS, WAF, bot, or abuse mitigation because of the test.
- Generator VUs are exhausted, iterations drop, or the source network reports dial timeouts or resets.
- Spend crosses the approved limit.

Stop immediately for corruption, cross-tenant leakage, security-boundary failure, or an instruction from Cloudflare.

## Failure attribution

| Signal | Classification |
| --- | --- |
| Dropped iterations or insufficient VUs | Generator ceiling |
| Dial timeout, socket exhaustion, router/NAT reset | Source-path ceiling |
| DDoS/security event matching generator traffic | Mitigation boundary |
| Independent probes healthy but generator failing | Generator or source-path issue |
| Independent probes and ordinary users failing | Service-impacting event; stop immediately |
| Worker latency/errors rise without generator or mitigation signals | Candidate application ceiling |
| Queue grows after offered load stops | Downstream or drain-capacity ceiling |

Only the final two rows can support an application or downstream ceiling, and only after repetition.

## Recovery and cleanup

1. Stop every generator and confirm no `k6` or orchestrator process remains.
2. Verify `/health`, MCP initialization, a lightweight call, and a bounded scan independently.
3. Confirm security mitigations clear and ordinary traffic returns to baseline.
4. Confirm queues drain and downstream errors normalize.
5. Revoke `BV_LOAD_TEST_KEY` and remove `BV_LOAD_TEST_ALLOW_IPS` plus any scoped test treatment.
6. Preserve sanitized summaries, metric exports, security-event identifiers, exact release, regions, and timings outside the repository.
7. Publish a dated report. Never claim a service ceiling when the limiter was the generator, network path, or Cloudflare mitigation.
