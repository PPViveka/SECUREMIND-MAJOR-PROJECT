/**
 * SageArmor Frontend Type Definitions
 * Shared domain models for scans, findings, jobs, and security metrics.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type VerificationVerdict = "verified" | "unconfirmed" | "refuted" | "not_applicable" | "inconclusive";
export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled" | "interrupted";

export interface VerificationGate {
  gate: string;
  passed: boolean;
  status: "pass" | "fail" | "skipped" | "error";
  detail: string;
}

export interface DynamicTrace {
  exploit_attempted?: boolean;
  sink_reached?: boolean;
  canary_detected?: boolean;
  isolation_used?: string;
  exit_code?: number;
  stdout?: string;
  stderr?: string;
}

export interface NormalizedFinding {
  id?: string;
  issue: string;
  severity: Severity;
  line: number;
  end_line?: number;
  code?: string;
  file?: string;
  cwe?: string;
  cwe_id?: string;
  recommendation?: string;
  explanation?: string;
  verified?: boolean;
  verification_status?: VerificationVerdict;
  verdict?: VerificationVerdict;
  dynamic_trace?: DynamicTrace;
  verification_gates?: VerificationGate[];
  suggested_fix?: string;
  diff?: string;
}

export interface SecurityScoreResponse {
  security_score: number;
  status: "secure" | "warning" | "critical";
  verified_count: number;
  unconfirmed_count: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  formula: string;
}

export interface JobStreamEvent {
  job_id: string;
  status: JobStatus;
  stage: string;
  progress: number;
  logs?: string[];
}

export interface BackendHealth {
  status: string;
  version?: string;
  docker_live?: boolean;
  isolation?: string;
  uptime_seconds?: number;
}
