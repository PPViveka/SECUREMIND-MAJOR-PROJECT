import type { Vulnerability } from './client';

/** Sandbox exploit-gate outcome for a finding. */
export type Verdict = NonNullable<Vulnerability['verification_status']>;

export function verdictOf(vuln: Pick<Vulnerability, 'verified' | 'verification_status' | 'verification'>): Verdict {
	if (vuln.verified) {
		return 'verified';
	}
	return vuln.verification_status ?? vuln.verification?.verdict ?? 'pending';
}

export const VERDICT_LABEL: Record<Verdict, string> = {
	verified: 'Exploit verified',
	inconclusive: 'Inconclusive',
	pending: 'Pending',
	not_run: 'Sandbox not run',
	not_applicable: 'No runtime check',
	unconfirmed: 'Unconfirmed',
	refuted: 'Refuted',
};

const VERDICT_RANK: Record<Verdict, number> = {
	verified: 0,
	inconclusive: 1,
	pending: 2,
	not_run: 2,
	not_applicable: 2,
	unconfirmed: 3,
	refuted: 4,
};

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Verified findings first, findings the sandbox attacked without success last; nothing is dropped. */
export function rankVulnerabilities<T extends Vulnerability>(items: T[]): T[] {
	return items
		.map((v, index) => ({ v, index }))
		.sort((a, b) =>
			(VERDICT_RANK[verdictOf(a.v)] ?? 2) - (VERDICT_RANK[verdictOf(b.v)] ?? 2)
			|| (SEVERITY_RANK[String(a.v.severity).toLowerCase()] ?? 5) - (SEVERITY_RANK[String(b.v.severity).toLowerCase()] ?? 5)
			|| a.index - b.index)
		.map(item => item.v);
}
