# Chaos harness validation

## Research and implementation plan

Reviewed against main `8a46da56`, following bv-cc doctrine `2e2fc95` and the six-layer testing methodology. Earlier SQ-439, SQ-440, and SQ-456 changes added domain deduplication, SSE parsing, quota reporting, and bounded release probes. This change preserves that work and repairs acceptance semantics.

| Confirmed gap | Repair | Offline verification |
| --- | --- | --- |
| Session initialization outages counted as rate limits | Classify actual initialization status; require exercised successful calls and zero hard failures | Full outage, network failure, quota-only, and successful burst controls |
| Credential validation accepted transport failures | Require successful MCP initialization and a valid owner-tier tool response; reject redirects and lower tiers | Transport, 403/503, malformed envelopes, missing tier, partner/free downgrade, and owner positive control |
| Empty or skipped results exited successfully | Default acceptance requires every named external regression check to pass | Empty, all-skipped, missing required check, explicit failure, and complete result controls |
| Python regressions omitted from CI | Run standard-library unittest discovery in required CI preflight | All `scripts/chaos/test_*.py` tests, with no live requests |
| Legacy runner expected session revival and tolerated failures | Retire its entry point with exit 2 and replacement guidance | Subprocess confirms retirement without network dependencies |

## Running offline

```bash
python3 -m unittest discover -s scripts/chaos -p 'test_*.py'
```

This command exercises harness logic, not the live service. CI runs it once in `preflight`, whose result feeds the required `build-and-test` check. It never launches a production burst.

## Live acceptance and diagnostics

`chaos-fix-regression.py` is the bounded read-only release probe. It accepts an owner credential through `BV_VERIFY_KEY` or the approved local key source. `chaos-test-clients.py` uses `BV_API_KEY` and includes concurrent traffic; run it only with authorization for that target. Both verify owner tier before suite execution and stop on missing credentials, transport failure, invalid response, or downgrade. Credentials never appear in curl argv; redirects do not carry credentials to another host.

Default exit codes:

- **0:** all required external checks passed with exercised coverage.
- **1:** an explicit failure, including owner preflight failure.
- **2:** incomplete coverage, including empty, missing, or quota-skipped required checks.

`--diagnostic` permits a partial investigation with at least one passing check and no failures. Its output explicitly says it is not acceptance evidence. Empty or entirely skipped diagnostics still exit 2. For the bounded regression probe, the internal latency check and the deliberately untriggered production OAuth rate-limit path remain `NOT-EXERCISED`; they are not among its six external acceptance checks.

## Boundaries

The synthetic all-tools matrix proves registry/dispatcher coverage under fixtures, not live auth or transport. Existing chaos tests explicitly characterize primary DoH 5xx without fallback and oversized MTA-STS handling; those are existing behavior findings, not absent tests repaired by these harness changes. No production fault injection or burst is part of the offline validation plan.
