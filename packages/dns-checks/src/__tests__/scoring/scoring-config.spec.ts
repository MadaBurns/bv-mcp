// SPDX-License-Identifier: BUSL-1.1

// Thin wrapper: runs the shared scoring-config suite against the SOURCE module.
// The built-package surface is exercised by test/scoring-config.spec.ts; the
// assertions live once in ./scoring-config.suite.ts.
import * as scoring from '../../scoring';
import { defineScoringConfigSuite } from './scoring-config.suite';

defineScoringConfigSuite(scoring);
