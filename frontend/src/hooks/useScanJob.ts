/**
 * SageArmor React Hook: useScanJob
 * Encapsulates scan lifecycle, SSE real-time streaming updates, and state management.
 */

import { useState, useCallback, useRef, useEffect } from "react";
import { NormalizedFinding, JobStatus } from "../types";

export interface ScanJobState {
  jobId: string | null;
  status: JobStatus | "idle";
  stage: string;
  progress: number;
  findings: NormalizedFinding[];
  logs: string[];
  error: string | null;
}

export function useScanJob(apiBaseUrl: string = "http://localhost:6060") {
  const [state, setState] = useState<ScanJobState>({
    jobId: null,
    status: "idle",
    stage: "",
    progress: 0,
    findings: [],
    logs: [],
    error: null,
  });

  const eventSourceRef = useRef<EventSource | null>(null);

  const startStream = useCallback(
    (jobId: string) => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      setState((prev) => ({ ...prev, jobId, status: "running", stage: "streaming", progress: 0 }));

      const es = new EventSource(`${apiBaseUrl}/v2/jobs/${jobId}/stream`);
      eventSourceRef.current = es;

      es.addEventListener("update", (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          setState((prev) => ({
            ...prev,
            status: data.status || prev.status,
            stage: data.stage || prev.stage,
            progress: data.progress ?? prev.progress,
            logs: data.logs ? [...prev.logs, ...data.logs] : prev.logs,
          }));
        } catch {
          // ignore stream parse glitches
        }
      });

      es.addEventListener("done", (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);
          setState((prev) => ({
            ...prev,
            status: data.status === "succeeded" ? "succeeded" : "failed",
            progress: 100,
          }));
        } finally {
          es.close();
        }
      });

      es.addEventListener("error", () => {
        es.close();
      });
    },
    [apiBaseUrl]
  );

  const reset = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    setState({
      jobId: null,
      status: "idle",
      stage: "",
      progress: 0,
      findings: [],
      logs: [],
      error: null,
    });
  }, []);

  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  return {
    ...state,
    startStream,
    reset,
  };
}
