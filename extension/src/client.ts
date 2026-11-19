import axios, { AxiosInstance } from 'axios';
import { SettingsManager } from './settings';
import { rankVulnerabilities } from './verdict';

export interface Vulnerability {
	finding_id?: string;
	schema_version?: string;
	title: string;
	description: string;
	severity: 'Critical' | 'High' | 'Medium' | 'Low';
	line: number | null;
	column: number;
	endLine: number | null;
	endColumn: number;
	attack_vector: string;
	attack_scenario: string;
	remediation: string;
	remediation_description: string;
	verified?: boolean;
	verification_status?: 'verified' | 'refuted' | 'inconclusive' | 'not_applicable' | 'not_run' | 'pending' | 'unconfirmed';
	verification?: { verdict?: Vulnerability['verification_status']; reason?: string };
	patch_status?: 'validated_patch' | 'unverified_draft' | 'none';
	validated_patch?: boolean;
	is_file_level?: boolean;
	range?: { start?: number; end?: number };
	dynamic_trace?: {
		sink_reached?: boolean;
		sink_line?: number | string;
		[key: string]: unknown;
	};
	unconfirmed_note?: string;
	cwe_id?: string;
	function_name?: string;
	file_path?: string;
	/** What the sandbox attack sent and what the dangerous call received. */
	evidence?: {
		payload?: string;
		payload_source?: 'fixed' | 'llm' | null;
		sink?: { kind: string; argument: string } | null;
		attempts?: { n: number; source: string; status: string }[];
		llm_used?: boolean;
		reason?: string;
	};
}

export interface ReviewResponse {
	vulnerabilities: Vulnerability[];
	language: string;
	analysis_mode: string;
	job_id?: string;
	status?: string;
	schema_version?: string;
	degraded?: boolean;
}

type RawVulnerability = Partial<Vulnerability> & {
	issue?: string;
	explanation?: string;
	poc_exploit_scenario?: string;
	suggested_fix?: string;
	remediation?: string | { patch?: string; description?: string };
	matched_code?: string;
	verified?: boolean;
	verification_status?: 'verified' | 'refuted' | 'inconclusive' | 'not_applicable' | 'not_run' | 'pending' | 'unconfirmed';
	verification?: Vulnerability['verification'];
	patch_status?: 'validated_patch' | 'unverified_draft' | 'none';
	validated_patch?: boolean;
	range?: Vulnerability['range'];
	dynamic_trace?: Vulnerability['dynamic_trace'];
	unconfirmed_note?: string;
	evidence?: Vulnerability['evidence'];
	cwe?: string;
	cwe_id?: string;
	function_name?: string;
	file_path?: string;
	line_number?: number;
};

export function normalizeReviewResponse(data: any, fallbackLanguage: string): ReviewResponse {
	const rawVulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
	const vulnerabilities: Vulnerability[] = rawVulns.map((v: RawVulnerability) => {
		const remediationObj =
			typeof v.remediation === 'object' && v.remediation !== null
				? (v.remediation as { patch?: string; description?: string })
				: null;

		const remediationPatch =
			remediationObj
				? (remediationObj.patch ?? '')
				: typeof v.remediation === 'string'
				? v.remediation
				: '';

		const remediationDescription =
			remediationObj
				? (remediationObj.description ?? '')
				: '';

		const hasExplicitLine =
			typeof v.range?.start === 'number' ||
			typeof v.line === 'number' ||
			typeof (v as any).start_line === 'number';

		const rawStart = typeof v.range?.start === 'number'
			? v.range.start
			: typeof v.line === 'number'
			? v.line
			: typeof (v as any).start_line === 'number'
			? (v as any).start_line
			: null;

		const rawEnd = typeof v.range?.end === 'number'
			? v.range.end
			: typeof v.endLine === 'number'
			? v.endLine
			: typeof (v as any).end_line === 'number'
			? (v as any).end_line
			: rawStart;

		const line = hasExplicitLine && rawStart !== null && !isNaN(rawStart)
			? Math.max(0, rawStart - 1)
			: null;

		const endLine = line !== null && rawEnd !== null && !isNaN(rawEnd)
			? Math.max(0, rawEnd - 1)
			: line;

		const column = typeof v.column === 'number' ? Math.max(0, v.column - 1) : 0;
		const endColumn = typeof v.endColumn === 'number'
			? Math.max(0, v.endColumn - 1)
			: typeof (v as any).end_column === 'number'
			? Math.max(0, (v as any).end_column - 1)
			: column + 1;

		const isFileLevel = line === null;

		const isValidatedPatch =
			v.patch_status === 'validated_patch' ||
			v.validated_patch === true ||
			(v as any).verified_patch === true;

		const patchStatus: Vulnerability['patch_status'] = isValidatedPatch
			? 'validated_patch'
			: (remediationPatch || v.suggested_fix)
			? 'unverified_draft'
			: 'none';

		return {
			finding_id: v.finding_id,
			schema_version: v.schema_version,
			title: v.title ?? v.issue ?? 'Security issue',
			description: v.description ?? v.explanation ?? 'Potential vulnerability detected.',
			severity: (v.severity as Vulnerability['severity']) ?? 'Medium',
			line,
			column,
			endLine,
			endColumn,
			is_file_level: isFileLevel,
			attack_vector: v.attack_vector ?? 'Unknown attack vector',
			attack_scenario: v.attack_scenario ?? v.poc_exploit_scenario ?? 'No scenario provided',
			remediation: remediationPatch || v.suggested_fix || 'Apply input validation and secure coding practices.',
			remediation_description:
				remediationDescription || 'Use the proposed fix and re-run scan to verify remediation.',
			verified: v.verified,
			// The specific status ('unconfirmed', 'not_run') beats the coarser schema verdict.
			verification_status: v.verification_status ?? v.verification?.verdict ?? (v.verified ? 'verified' : 'pending'),
			verification: v.verification,
			patch_status: patchStatus,
			validated_patch: isValidatedPatch,
			dynamic_trace: v.dynamic_trace,
			unconfirmed_note: v.unconfirmed_note,
			evidence: v.evidence,
			cwe_id: v.cwe_id ?? v.cwe,
			function_name: v.function_name,
			file_path: v.file_path,
		};
	});

	return {
		vulnerabilities: rankVulnerabilities(vulnerabilities),
		language: data?.language ?? fallbackLanguage,
		analysis_mode: data?.analysis_mode ?? 'unknown',
		job_id: data?.job_id,
		status: data?.status,
		schema_version: data?.schema_version,
		degraded: Boolean(data?.degraded),
	};
}

export function mapBackendError(error: any, backendUrl: string): string {
	if (error?.response?.status === 429) {
		const retryAfter = error.response?.data?.retry_after_seconds || 5;
		return `Quota exceeded. Retry in ${retryAfter} seconds`;
	}
	if (error?.response?.status === 401) {
		return 'Invalid API key. Check Sage Armor settings';
	}
	if (error?.response?.status >= 500) {
		return 'Backend server error. Please retry shortly.';
	}
	if (error?.code === 'ECONNREFUSED') {
		return `Cannot connect to backend at ${backendUrl}`;
	}
	if (error?.code === 'ECONNABORTED') {
		return 'Backend request timed out. Check network or backend health.';
	}
	if (error?.message) {
		return `Backend error: ${error.message}`;
	}
	return 'Backend error: Unknown error';
}

export class ExtensionClient {
	private client: AxiosInstance;
	private settingsManager: SettingsManager;
	private lastRequestTime = 0;
	private requestCount = 0;

	constructor(settingsManager: SettingsManager) {
		this.settingsManager = settingsManager;
		this.client = axios.create({
			baseURL: settingsManager.backendUrl,
			timeout: 30000, // 30 seconds
		});
	}

	async reviewCode(
		code: string,
		language: string,
		mode: string = this.settingsManager.scanMode,
		asyncVerify = false
	): Promise<ReviewResponse> {
		try {
			const validation = this.settingsManager.validateSettings();
			if (validation) {
				throw new Error(validation);
			}

			this.client.defaults.baseURL = this.settingsManager.backendUrl;

			const response = await this.client.post<any>('/review', {
				code,
				language,
				router_mode: mode,
				async_verify: asyncVerify,
			});

			return normalizeReviewResponse(response.data, language);
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async getReviewStatus(jobId: string): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.get(`/review/status?job_id=${encodeURIComponent(jobId)}`);
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async pollVerificationJob(jobId: string, timeoutMs = 15000, intervalMs = 500): Promise<ReviewResponse> {
		const startTime = Date.now();
		while (Date.now() - startTime < timeoutMs) {
			const job = await this.getReviewStatus(jobId);
			if (job?.status === 'completed' && job.result) {
				return normalizeReviewResponse(job.result, job.language || 'python');
			}
			if (job?.status === 'failed' || job?.status === 'cancelled') {
				throw new Error(job.summary || `Async verification ${job.status}`);
			}
			await new Promise((resolve) => setTimeout(resolve, intervalMs));
		}
		throw new Error('Verification polling timed out');
	}

	async getBackendHealth(): Promise<{ status: string; degraded: boolean; reason?: string; provider?: string; model?: string }> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.get('/healthz');
			return res.data;
		} catch (error: any) {
			return {
				status: 'offline',
				degraded: true,
				reason: mapBackendError(error, this.settingsManager.backendUrl),
			};
		}
	}

	async testConnection(): Promise<boolean> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			
			// Try to call a simple endpoint to test connection
			const response = await this.client.post('/review', {
				code: '# test',
				language: 'python',
			}, {
				timeout: 5000,
			});

			return response.status === 200;
		} catch (error) {
			console.error('Connection test failed:', error);
			return false;
		}
	}

	async getAttackPath(code: string, language = 'python'): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.post('/attack-path', { code, language });
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async getRiskScore(vulnerabilities: any[], code = ''): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.post('/risk-score', { vulnerabilities, code });
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async askCopilot(question: string, vulnerabilities: any[] = [], code = ''): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.post('/copilot', { question, vulnerabilities, code });
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async startRepoScan(repoUrl: string, query = '', branch?: string, topK = 3): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.post('/repo-scan/start', {
				repo_url: repoUrl,
				query,
				branch,
				top_k: topK,
			});
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async getRepoScanStatus(jobId: string): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.get(`/repo-scan/status?job_id=${encodeURIComponent(jobId)}`);
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async cancelRepoScan(jobId: string): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.post('/repo-scan/cancel', { job_id: jobId });
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	async startAutofix(repoUrl: string, vulnerabilities: any[], mode = 'suggest'): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.post('/repo-autofix/start', {
				repo_url: repoUrl,
				vulnerabilities,
				mode,
			});
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	/**
	 * Ask the backend's verified fix loop to patch one finding in `code` and wait for the result.
	 * `onProgress` receives the job's latest log line.
	 */
	async generateVerifiedFix(
		code: string,
		language: string,
		finding: Record<string, unknown>,
		onProgress?: (message: string) => void,
		isCancelled?: () => boolean,
	): Promise<any> {
		this.client.defaults.baseURL = this.settingsManager.backendUrl;
		let jobId: string;
		try {
			const res = await this.client.post('/repo-autofix/start', {
				code,
				language,
				vulnerabilities: [finding],
				mode: 'suggest',
			});
			jobId = res.data?.job_id;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
		if (!jobId) {
			throw new Error('Backend did not start a fix job');
		}
		const deadline = Date.now() + 10 * 60 * 1000;
		while (Date.now() < deadline) {
			if (isCancelled?.()) {
				throw new Error('Cancelled');
			}
			await new Promise((r) => setTimeout(r, 2000));
			const job = await this.getAutofixStatus(jobId);
			const last = Array.isArray(job?.logs) ? job.logs[job.logs.length - 1] : undefined;
			const text = typeof last === 'string' ? last : last?.message;
			if (text) {
				onProgress?.(String(text));
			}
			if (job?.status === 'completed') {
				return job;
			}
			if (job?.status === 'failed' || job?.status === 'interrupted') {
				throw new Error(job?.error || text || 'The fix job failed');
			}
		}
		throw new Error('Timed out waiting for the verified fix');
	}

	async getAutofixStatus(jobId: string): Promise<any> {
		try {
			this.client.defaults.baseURL = this.settingsManager.backendUrl;
			const res = await this.client.get(`/repo-autofix/status?job_id=${encodeURIComponent(jobId)}`);
			return res.data;
		} catch (error: any) {
			throw new Error(mapBackendError(error, this.settingsManager.backendUrl));
		}
	}

	updateBaseUrl(url: string) {
		this.client.defaults.baseURL = url;
	}
}
