/**
 * SageArmor Frontend API Service
 * Encapsulates all backend REST calls, authentication headers, error mapping,
 * job polling, and graceful fallback behavior.
 */

import { auth } from './auth';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:6060';

export interface BackendHealth {
  status: 'online' | 'degraded' | 'offline';
  provider: string;
  model: string;
  degraded: boolean;
  reason?: string;
  dockerAvailable?: boolean;
}

export interface VerificationGate {
  gate: string;
  passed: boolean;
  detail: string;
}

export interface NormalizedFinding {
  finding_id: string;
  schema_version?: string;
  issue: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  explanation?: string;
  file?: string;
  line?: number | null;
  endLine?: number | null;
  poc_exploit_scenario?: string;
  remediation?: { patch?: string; explanation?: string };
  suggested_fix?: string;
  verified?: boolean;
  verification_status?: 'verified' | 'refuted' | 'inconclusive' | 'not_applicable' | 'pending';
  verification?: { verdict?: string; reason?: string };
  patch_status?: 'validated_patch' | 'unverified_draft' | 'none';
  dynamic_trace?: {
    sink_reached?: boolean;
    sink_line?: number | string;
    vector_used?: string;
    harness_output?: string;
  };
}

export interface ReviewResponseEnvelope {
  job_id?: string;
  status?: string;
  analysis_mode: string;
  vulnerabilities: NormalizedFinding[];
  degraded?: boolean;
  degraded_state?: Record<string, unknown>;
  telemetry?: Record<string, unknown>;
}

export interface JobStatusResponse {
  job_id: string;
  status: 'running' | 'completed' | 'failed' | 'interrupted' | 'cancelled';
  stage: string;
  progress: number;
  summary?: string;
  logs?: string[];
  events?: Array<{ timestamp: number; type: string; detail: string }>;
  metrics?: Record<string, number>;
  result?: {
    vulnerabilities?: NormalizedFinding[];
    status?: string;
  };
  results?: any[];
  pr_url?: string;
  modified_files?: any;
  error?: string;
}

function getHeaders(customHeaders: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...customHeaders,
  };
  const token = auth.getGitHubToken();
  if (token) {
    headers['X-GitHub-Token'] = token;
  }
  return headers;
}

export async function checkBackendHealth(): Promise<BackendHealth> {
  try {
    const res = await fetch(`${API_BASE_URL}/healthz`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!res.ok) {
      return {
        status: 'degraded',
        provider: 'Unknown',
        model: 'Unknown',
        degraded: true,
        reason: `HTTP ${res.status}`,
      };
    }
    const data = await res.json();
    return {
      status: data.status === 'ok' ? (data.degraded ? 'degraded' : 'online') : 'degraded',
      provider: data.provider || 'Amazon Bedrock',
      model: data.model || 'Claude 3.5 Sonnet',
      degraded: Boolean(data.degraded),
      reason: data.degraded_reason,
      dockerAvailable: data.docker_available ?? true,
    };
  } catch (err: any) {
    return {
      status: 'offline',
      provider: 'None',
      model: 'None',
      degraded: true,
      reason: err?.message || 'Connection refused',
    };
  }
}

export async function reviewCode(
  code: string,
  language = 'python',
  routerMode = 'balanced',
  asyncVerify = false
): Promise<ReviewResponseEnvelope> {
  const res = await fetch(`${API_BASE_URL}/review`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({
      code,
      language,
      router_mode: routerMode,
      async_verify: asyncVerify,
    }),
  });

  if (res.status === 401) {
    throw new Error('Authentication required by backend.');
  }
  if (res.status === 429) {
    const data = await res.json().catch(() => ({}));
    throw new Error(`Rate limit exceeded. Retry in ${data.retry_after_seconds || 5}s.`);
  }
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.error || `Review failed with HTTP ${res.status}`);
  }

  return res.json();
}

export async function getReviewJobStatus(jobId: string): Promise<JobStatusResponse> {
  const res = await fetch(`${API_BASE_URL}/review/status?job_id=${encodeURIComponent(jobId)}`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to query job status (${res.status})`);
  }
  return res.json();
}

export async function pollVerificationJob(
  jobId: string,
  onProgress?: (job: JobStatusResponse) => void,
  maxAttempts = 40,
  intervalMs = 500
): Promise<JobStatusResponse> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const job = await getReviewJobStatus(jobId);
    if (onProgress) onProgress(job);
    if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
      return job;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('Verification polling timed out');
}

export async function startRepoScan(
  repoUrl: string,
  query = '',
  branch?: string,
  topK = 3
): Promise<{ job_id: string; status: string }> {
  const res = await fetch(`${API_BASE_URL}/repo-scan/start`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({
      repo_url: repoUrl,
      query,
      branch,
      top_k: topK,
      github_token: auth.getGitHubToken(),
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to start repository scan (${res.status})`);
  }
  return res.json();
}

export async function getRepoScanStatus(jobId: string): Promise<JobStatusResponse> {
  const res = await fetch(`${API_BASE_URL}/repo-scan/status?job_id=${encodeURIComponent(jobId)}`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to query scan job status (${res.status})`);
  }
  return res.json();
}

export async function cancelRepoScan(jobId: string): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/repo-scan/cancel`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ job_id: jobId }),
  });
  return res.json();
}

export async function startAutoFix(payload: {
  repoUrl?: string;
  code?: string;
  vulnerabilities: any[];
  mode?: 'suggest' | 'fix' | 'pr';
  branch?: string;
  language?: string;
}): Promise<{ job_id: string; status: string }> {
  const res = await fetch(`${API_BASE_URL}/repo-autofix/start`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({
      repo_url: payload.repoUrl,
      code: payload.code,
      vulnerabilities: payload.vulnerabilities,
      mode: payload.mode || 'suggest',
      branch: payload.branch,
      language: payload.language || 'python',
      github_token: auth.getGitHubToken(),
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to start autofix job (${res.status})`);
  }
  return res.json();
}

export async function getAutoFixStatus(jobId: string): Promise<JobStatusResponse> {
  const res = await fetch(`${API_BASE_URL}/repo-autofix/status?job_id=${encodeURIComponent(jobId)}`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to query autofix status (${res.status})`);
  }
  return res.json();
}

export async function getRiskScore(vulnerabilities: any[], code = ''): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/risk-score`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ vulnerabilities, code }),
  });
  return res.json();
}

export async function getAttackPath(code: string, vulnerabilities: any[] = [], language = 'python'): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/attack-path`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ code, vulnerabilities, language }),
  });
  return res.json();
}

export async function simulateBreach(vulnerabilities: any[], code = ''): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/simulate`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ vulnerabilities, code }),
  });
  return res.json();
}

export async function askCopilot(question: string, vulnerabilities: any[] = [], code = ''): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/copilot`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ question, vulnerabilities, code }),
  });
  return res.json();
}
