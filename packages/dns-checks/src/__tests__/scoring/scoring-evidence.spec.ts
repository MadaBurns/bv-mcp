// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-evidence suite against the SOURCE module.
// The built-package surface is exercised by test/scoring-evidence.spec.ts; the
// assertions live once in ./scoring-evidence.suite.ts.
import * as scoring from '../../scoring';
import { defineScoringEvidenceSuite } from './scoring-evidence.suite';

defineScoringEvidenceSuite(scoring);
