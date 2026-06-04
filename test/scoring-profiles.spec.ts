// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-profiles suite against the BUILT package
// (`@blackveil/dns-checks/scoring`), so source↔dist/DTS drift is caught. The
// source surface is exercised by the same suite in
// packages/dns-checks/src/__tests__/scoring/scoring-profiles.spec.ts.
import * as scoring from '@blackveil/dns-checks/scoring';
import { defineScoringProfilesSuite } from '../packages/dns-checks/src/__tests__/scoring/scoring-profiles.suite';

defineScoringProfilesSuite(scoring);
