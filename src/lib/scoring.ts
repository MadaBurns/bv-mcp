/**
 * DNS Security Scoring Library
 *
 * Public scoring surface re-exporting the scoring model and scan aggregation engine.
 */

export {
	CATEGORY_DISPLAY_WEIGHTS,
	SEVERITY_PENALTIES,
	buildCheckResult,
	computeCategoryScore,
	createFinding,
	inferFindingConfidence,
	type CheckCategory,
	type CheckResult,
	type Finding,
	type FindingConfidence,
	type ScanScore,
	type Severity,
} from './scoring-model';

export { computeScanScore, scoreToGrade } from './scoring-engine';
