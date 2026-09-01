# Production capacity test report — 2026-09-01

## Executive conclusion

The production service ceiling was **not established**.

The local Auckland-origin edge test completed five-minute 800-RPS stages, but later stages activated Cloudflare DDoS mitigation and subsequent repetitions showed generator exhaustion, dial timeouts, connection resets, and dropped iterations. These are exclusion conditions for a service-capacity result.

Authenticated protocol, useful-work, and heavy-work lanes were not executed. The temporary-credential release could not pass its mandatory production D1 schema preflight because the Cloudflare D1 control plane repeatedly returned internal error code 7500. The safety gate was not bypassed.

## Configuration

- Origin: production MCP service behind Cloudflare.
- Generator: one local Auckland-origin machine.
- Lane: edge `GET /health`.
- Stages: five minutes with two-minute recovery.
- Production remained on the release preceding v3.73.2; v3.73.2 was merged and tagged but not deployed during the exercise.
- No permanent internal development credential was used.
- No temporary production credential or WAF exception was created.

## Valid observations

| Offered rate | Requests | Failures | p95 | p99 | Maximum | Outcome |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 10 RPS | 3,001 | 0% | 30.31 ms | 42.60 ms | 260.60 ms | Stable single stage |
| 25 RPS | 7,501 | 0% | 31.72 ms | 51.70 ms | 585.36 ms | Stable single stage |
| 50 RPS | 15,001 | 0% | 28.77 ms | 45.94 ms | 842.61 ms | Stable single stage |
| 100 RPS | 30,001 | 0% | 27.69 ms | 52.54 ms | 664.43 ms | Stable single stage |
| 200 RPS | 60,001 | 0% | 28.09 ms | 49.21 ms | 726.75 ms | Stable single stage |
| 400 RPS | 120,001 | 0% | 27.31 ms | 48.32 ms | 540.90 ms | Stable single stage |
| 800 RPS | 240,001 | 0% | 26.52 ms | 45.13 ms | 526.93 ms | Stable single stage |
| 800 RPS repeat | 240,000 | 0% | 25.43 ms | 41.50 ms | 529.81 ms | Stable single repetition |

These stages prove only that this source path delivered 800 successful edge requests per second for five minutes on those attempts.

## Invalidated boundary observations

- The 1,600-RPS stage aborted with approximately 87% failed requests.
- Refinement at 960 and 1,120 RPS aborted with approximately 99% failures.
- A repeated 800-RPS stage exhausted 1,600 VUs, dropped 12,593 iterations, produced dial timeouts and resets, and triggered the independent-probe abort.
- A following 800-RPS attempt exceeded the failure threshold and aborted.
- Cloudflare security telemetry identified DDoS-rule activation caused by the test.

Low latency among completed responses does not convert these stages into application-capacity evidence.

## Required figures

| Figure | Result |
| --- | --- |
| Peak accepted RPS | At least 800 RPS for a completed five-minute edge stage |
| Maximum stable RPS | Not established; no boundary rate passed three repetitions without exclusions |
| Sustained RPS | Not established; no qualifying 30-minute hold completed |
| Recommended operating limit | Not established |

Do not use 800 RPS as a production rate limit or capacity promise.

## Recovery

- All generators stopped and no load process remained active.
- Three post-test `/health` probes returned HTTP 200 in approximately 46–49 ms.
- No DDoS or WAF protection was weakened.
- No temporary credential or security exception required cleanup.

## Next gates

1. Resolve the D1 preflight failure and deploy the guarded credential.
2. Coordinate planned traffic with Cloudflare.
3. Use distributed dedicated generators with independent generator-health telemetry.
4. Rehearse in production-equivalent staging.
5. Restart at a conservative baseline, not the prior failure rate.
6. Complete three boundary repetitions, a 30-minute hold, and the 80% endurance stage before calculating an operating limit.
