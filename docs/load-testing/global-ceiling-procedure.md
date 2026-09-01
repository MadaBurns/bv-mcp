# Global ceiling measurement procedure

## Objective

Determine the maximum globally distributed throughput the production service can sustain while preserving latency, correctness, availability, and ordinary-user experience.

A single-host test can validate the harness and establish a source-path ceiling. It cannot establish a global service ceiling.

## Capacity lanes

| Lane | Workload | Purpose |
| --- | --- | --- |
| Edge | `GET /health` | Cloudflare routing, DDoS/WAF, TLS, and HTTP capacity |
| Protocol | Authenticated MCP `tools/list` | Session and serialization capacity |
| Useful | `check_spf`, cached and uncached | DNS and lightweight processing capacity |
| Heavy | `scan_domain` and bounded investigation operations | Queue, upstream, and downstream capacity |
| Mixed | Weighted combination of all lanes | Production-shaped capacity and contention |

## Stable-stage criteria

A stage is stable only when all of the following hold:

- HTTP and MCP semantic success are at least 99.9%.
- Lightweight p95 latency is at most 500 ms.
- Full-scan p95 latency is at most 10 seconds.
- Schema and correctness failures are zero.
- Generator dropped iterations are zero.
- Independent ordinary-user probes remain healthy.
- Queue backlog drains to its pre-test range.
- No persistent downstream, Durable Object, or ordinary-user degradation occurs.
- Cloudflare has not activated DDoS, WAF, bot, or abuse mitigation because of the test.

A stage rejected by the generator, source network, or Cloudflare mitigation is not evidence of the application ceiling.

## Required preparation

1. Approve the test window, maximum offered rate, and spend ceiling.
2. Confirm Cloudflare's current load-testing policy and notify Cloudflare when required.
3. Create a temporary `BV_LOAD_TEST_KEY` secret and configure `BV_LOAD_TEST_ALLOW_IPS` for only approved generator addresses.
4. Never use `BV_INTERNAL_DEV_KEY_2` or expose a permanent owner credential.
5. Identify Cloudflare rules that may classify the planned traffic. Do not disable account-wide DDoS protection.
6. Establish and test a kill switch reachable by every generator.
7. Record baseline Worker, Durable Object, KV, D1, queue, binding, error, latency, and cost signals.
8. Confirm the deployed release and the `bv_load_test` analytics identity.

## Generator topology

For a global result, use synchronized generators in at least Auckland or Sydney, Singapore, Mumbai, Frankfurt, London, Virginia, Oregon, and Sao Paulo. Use unique MCP sessions per virtual client.

Each generator records offered, sent, completed, and dropped work; HTTP and MCP outcome; p50/p95/p99/max latency; connection and TLS timing; response size; schema failures; WAF/quota/mitigation outcomes; region; and workload.

## Workload mix

| Workload | Share |
| --- | ---: |
| MCP initialization/session traffic | 5% |
| `tools/list` and discovery | 10% |
| Cached lightweight DNS checks | 35% |
| Uncached lightweight checks | 20% |
| `scan_domain` | 20% |
| Investigation status/report operations | 10% |

Use BlackVeil-controlled domains and reserved synthetic domains only. Do not generate invasive people-centric traffic or repeatedly scan unrelated third parties.

## Stages

1. Validate contracts locally and against production-equivalent staging.
2. Run each lane at 10 RPS for five minutes and reconcile generator and Cloudflare counts within 2%.
3. Run five-minute staircase stages at 25, 50, 100, 200, 400, 800, 1,600, and 3,200 global RPS, with two-minute recovery intervals.
4. On the first instability, stop doubling and use 10–20% increments.
5. At the suspected boundary, run three five-minute repetitions per rate. Stop after two consecutive unstable stages.
6. Hold the highest repeated stable rate for 30 minutes, then 80% of that rate for two hours.
7. Only after endurance, test bounded bursts of 2x for 10 seconds, 3x for five seconds, and 5x for one second.

Do not advance while failure attribution is uncertain.

## Result definitions

- **Peak accepted RPS:** highest momentary successful throughput.
- **Maximum stable RPS:** highest repeated five-minute stage satisfying every stable-stage criterion.
- **Sustained RPS:** highest rate maintained for 30 minutes.
- **Recommended operating limit:** normally 60–70% of sustained capacity, reduced further when downstream or regional headroom requires it.

Report these figures by region and workload. If evidence is incomplete, report “not established” rather than substituting a transient peak.
