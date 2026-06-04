// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-model suite against the SOURCE module.
// The built-package surface is exercised by test/scoring-model.spec.ts; the
// assertions live once in ./scoring-model.suite.ts.
import * as scoring from '../../scoring';
import { defineScoringModelSuite } from './scoring-model.suite';

defineScoringModelSuite(scoring);
