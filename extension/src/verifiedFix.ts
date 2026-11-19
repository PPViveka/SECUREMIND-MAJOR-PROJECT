import type { Vulnerability } from './client';

/** Result of the backend's gated fix loop for one finding (an autofix job result). */
export type BackendPatchStatus = 'verified' | 'unverified_draft' | 'failed';

export interface FixGateResult {
	gate: string;
	label?: string;
	status?: string;
	detail: string;
}

export interface GatedFix {
	patch_status: BackendPatchStatus;
	fixed_code?: string;
	diff?: string;
	explanation?: string;
	verification_gates?: FixGateResult[];
	fixes?: { failed_gate?: { label?: string; detail?: string } | null; patch_status?: string }[];
}

/** The finding as the backend's fix loop expects it (1-based line, with the sandbox evidence). */
export function buildFixFinding(v: Vulnerability): Record<string, unknown> {
	return {
		issue: v.title,
		explanation: v.description,
		severity: v.severity,
		cwe_id: v.cwe_id,
		function_name: v.function_name,
		line_number: typeof v.line === 'number' ? v.line + 1 : undefined,
		file_path: v.file_path,
		evidence: v.evidence,
		verification_status: v.verification_status,
	};
}

/** Findings from a repository scan, kept only when they name the file they are in. */
export function repoFindingsForAutofix(scanJob: any): Record<string, unknown>[] {
	const list: any[] = scanJob?.vulnerabilities_full || scanJob?.vulnerabilities_partial || scanJob?.vulnerabilities || [];
	return list
		.filter((v) => v && typeof v === 'object' && (v.file_path || v.path))
		.map((v) => ({
			issue: v.issue ?? v.title,
			severity: v.severity,
			cwe_id: v.cwe_id ?? v.cwe,
			file_path: v.file_path ?? v.path,
			line_number: v.line_number ?? v.line,
			function_name: v.function_name,
			explanation: v.explanation ?? v.description,
			evidence: v.evidence,
			verification_status: v.verification_status,
		}));
}

/** The fix result of a finished snippet autofix job, or null if it produced none. */
export function pickGatedFix(job: any): GatedFix | null {
	const results: any[] = Array.isArray(job?.results) ? job.results : [];
	const r = results.find((x) => x && typeof x.fixed_code === 'string');
	if (!r) {
		return null;
	}
	const status: BackendPatchStatus =
		r.patch_status === 'verified' ? 'verified' : r.patch_status === 'failed' ? 'failed' : 'unverified_draft';
	return { ...r, patch_status: status };
}

/** Maps the fix loop's outcome onto the finding's patch_status. */
export function toFindingPatchStatus(status: BackendPatchStatus): NonNullable<Vulnerability['patch_status']> {
	return status === 'verified' ? 'validated_patch' : status === 'unverified_draft' ? 'unverified_draft' : 'none';
}

/** The first gate that did not pass, as one sentence. */
export function failedGateSummary(fix: GatedFix): string {
	const gate = (fix.verification_gates || []).find((g) => g.status && g.status !== 'pass');
	const fromFix = fix.fixes?.find((f) => f.failed_gate)?.failed_gate;
	const label = gate?.label || fromFix?.label || 'A verification gate';
	const detail = (gate?.detail || fromFix?.detail || 'did not pass').replace(/^Gate [A-E] (PASS|FAIL|ERROR|SKIPPED):\s*/, '');
	return `${label}: ${detail}`;
}

/** User-facing message. "Verified fix" is used only when every gate passed. */
export function describeGatedFix(title: string, fix: GatedFix): string {
	if (fix.patch_status === 'verified') {
		return `Verified fix for ${title}: the recorded exploit and new attacks are blocked, normal inputs behave the same, and the security rescan is clean.`;
	}
	if (fix.patch_status === 'failed') {
		return `No usable fix for ${title}. ${failedGateSummary(fix)}`;
	}
	return `The fix for ${title} could not be verified. ${failedGateSummary(fix)}`;
}
