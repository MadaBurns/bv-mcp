// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-profiles suite against the SOURCE module.
// The built-package surface is exercised by test/scoring-profiles.spec.ts; the
// assertions + expected values live once in ./scoring-profiles.suite.ts.
import * as scoring from '../../scoring';
import { defineScoringProfilesSuite } from './scoring-profiles.suite';

defineScoringProfilesSuite(scoring);
