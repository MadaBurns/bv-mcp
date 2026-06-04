// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-engine suite against the SOURCE module.
// The built-package surface is exercised by test/scoring-engine.spec.ts; the
// assertions live once in ./scoring-engine.suite.ts.
import * as scoring from '../../scoring';
import { defineScoringEngineSuite } from './scoring-engine.suite';

defineScoringEngineSuite(scoring);
