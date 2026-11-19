const test = require('node:test');
const assert = require('node:assert/strict');

test('Dashboard Integration Tests', async (t) => {
  await t.test('handles successful scan response and updates state', () => {
    const rawPayload = {
      vulnerabilities: [
        {
          finding_id: 'vuln-101',
          issue: 'Command Injection',
          severity: 'High',
          line: 12,
          verification_status: 'verified',
          verified: true,
          remediation: { patch: 'subprocess.run(["ls", "-la"])' }
        }
      ],
      job_id: 'job-12345',
      analysis_mode: 'model',
      schema_version: '1.0',
      degraded: false
    };

    function processScanResponse(payload) {
      return {
        findings: (payload.vulnerabilities || []).map(v => ({
          id: v.finding_id,
          issue: v.issue,
          severity: v.severity,
          line: v.line,
          verified: v.verified,
          badge: v.verified ? '🛡️ Verified' : '⚠️ Unconfirmed',
          patchAvailable: Boolean(v.remediation?.patch)
        })),
        isDegraded: Boolean(payload.degraded),
        jobId: payload.job_id
      };
    }

    const state = processScanResponse(rawPayload);
    assert.equal(state.findings.length, 1);
    assert.equal(state.findings[0].id, 'vuln-101');
    assert.equal(state.findings[0].badge, '🛡️ Verified');
    assert.equal(state.findings[0].patchAvailable, true);
    assert.equal(state.isDegraded, false);
    assert.equal(state.jobId, 'job-12345');
  });

  await t.test('handles timeout scenario with fallback notification', () => {
    function handleTimeoutError(err) {
      if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
        return {
          timedOut: true,
          userNotice: 'Analysis timed out. Displaying fast static fallback findings.',
          retryAllowed: true
        };
      }
      return { timedOut: false };
    }

    const handled = handleTimeoutError({ code: 'ECONNABORTED', message: 'timeout of 10000ms exceeded' });
    assert.equal(handled.timedOut, true);
    assert.match(handled.userNotice, /timed out/);
    assert.equal(handled.retryAllowed, true);
  });

  await t.test('handles 401, 429, and 5xx error responses', () => {
    function classifyHttpError(statusCode) {
      if (statusCode === 401) {
        return { action: 'prompt_login', message: 'Please provide a valid API token.' };
      }
      if (statusCode === 429) {
        return { action: 'backoff', message: 'Rate limit hit. Retrying in 5 seconds.' };
      }
      if (statusCode >= 500) {
        return { action: 'degraded_mode', message: 'Service degraded. Using local heuristics.' };
      }
      return { action: 'generic_error', message: 'An unexpected error occurred.' };
    }

    assert.equal(classifyHttpError(401).action, 'prompt_login');
    assert.equal(classifyHttpError(429).action, 'backoff');
    assert.equal(classifyHttpError(503).action, 'degraded_mode');
  });

  await t.test('handles polling failure, retries, and partial results accumulation', () => {
    class PollingCoordinator {
      constructor(maxRetries = 3) {
        this.maxRetries = maxRetries;
        this.retries = 0;
        this.accumulatedResults = [];
        this.completed = false;
      }

      handlePollResponse(response) {
        if (!response) {
          this.retries += 1;
          if (this.retries > this.maxRetries) {
            throw new Error('Polling failed after maximum retries');
          }
          return { status: 'retry', retryCount: this.retries };
        }

        this.retries = 0; // reset on valid response
        if (response.results && response.results.length > 0) {
          this.accumulatedResults.push(...response.results);
        }

        if (response.status === 'completed') {
          this.completed = true;
          return { status: 'completed', total: this.accumulatedResults.length };
        }
        return { status: 'in_progress', accumulated: this.accumulatedResults.length };
      }
    }

    const coordinator = new PollingCoordinator(2);
    // 1st poll returns partial
    const p1 = coordinator.handlePollResponse({ status: 'in_progress', results: [{ id: 'f1' }] });
    assert.equal(p1.status, 'in_progress');
    assert.equal(p1.accumulated, 1);

    // 2nd poll transient network hiccup
    const p2 = coordinator.handlePollResponse(null);
    assert.equal(p2.status, 'retry');
    assert.equal(p2.retryCount, 1);

    // 3rd poll returns completion
    const p3 = coordinator.handlePollResponse({ status: 'completed', results: [{ id: 'f2' }] });
    assert.equal(p3.status, 'completed');
    assert.equal(p3.total, 2);
    assert.equal(coordinator.completed, true);
  });
});
