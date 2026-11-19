export { normalizeReviewResponse, mapBackendError } from './client';
export {
	filterBySeverity,
	summarizeVulnerabilities,
	isSupportedLanguage,
	isSupportedExtension,
	getLanguageForExtension,
} from './scanUtils';
export {
	normalizeRemediation,
	createDiffHunk,
	applyPatchPreservingContext,
} from './fixUtils';
export {
	buildFixFinding,
	repoFindingsForAutofix,
	pickGatedFix,
	toFindingPatchStatus,
	describeGatedFix,
	failedGateSummary,
} from './verifiedFix';
