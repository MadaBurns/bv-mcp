// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-config suite against the BUILT package
// (`@blackveil/dns-checks/scoring`), so source↔dist/DTS drift is caught. The
// source surface is exercised by the same suite in
// packages/dns-checks/src/__tests__/scoring/scoring-config.spec.ts.
import * as scoring from '@blackveil/dns-checks/scoring';
import { defineScoringConfigSuite } from '../packages/dns-checks/src/__tests__/scoring/scoring-config.suite';

defineScoringConfigSuite(scoring);
