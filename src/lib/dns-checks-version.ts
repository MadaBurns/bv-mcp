// SPDX-License-Identifier: BUSL-1.1

/**
 * Version of the `@blackveil/dns-checks` scoring **engine package** bundled into
 * this build — a different namespace from `SCORING_MODEL_VERSION` (the scoring
 * *policy* semver in `lib/scoring-version.ts`) and from `SERVER_VERSION` (the
 * deployed Worker/npm build).
 *
 * Why this exists (issue #707): `scan_domain` stamped only `scoringModelVersion`,
 * which is semver-shaped and sits in the same numeric range as the package
 * version. Twice — 2026-08-12 (package 1.15.0 vs model 1.8.0) and 2026-08-19
 * (package 1.18.0 vs model 1.10.0) — a consuming project read the model version
 * as the package version, concluded the hosted service was eight minors behind
 * its own vendored copy, and opened an "engine version gap" investigation that
 * was refuted as namespace confusion. Emitting both side by side makes the
 * distinction visible in a single response instead of requiring the reader to
 * already know it.
 *
 * SOURCE: the package's own exported version constant, so the value always
 * describes the code actually bundled. `@blackveil/dns-checks` publishes no
 * `./package.json` export subpath, so the manifest cannot be imported across the
 * workspace boundary; reaching in with a relative path would also hardcode the
 * *workspace* version into builds that resolve a different installed copy.
 * `PARITY_CORPUS_VERSION` is version-locked to that manifest — the contract test
 * `packages/dns-checks/src/__tests__/parity-corpus.contract.test.ts` asserts
 * `pkg.version === PARITY_CORPUS_VERSION` — so it is the manifest value, read
 * through the package's public API. `test/scan-version-stamps.spec.ts` re-anchors
 * the emitted field to the manifest directly, so drift fails a test rather than
 * shipping.
 */

import { PARITY_CORPUS_VERSION } from '@blackveil/dns-checks';

export const DNS_CHECKS_PACKAGE_VERSION: string = PARITY_CORPUS_VERSION;
