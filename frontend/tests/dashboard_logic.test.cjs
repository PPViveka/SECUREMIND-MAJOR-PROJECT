const test = require('node:test');
const assert = require('node:assert/strict');

// Dashboard logic test suite
test('Dashboard Logic & State Handlers', async (t) => {
  await t.test('Score calculation and risk tier mapping', () => {
    function computeRiskTier(score) {
      if (score >= 80) return 'CRITICAL';
      if (score >= 60) return 'HIGH';
      if (score >= 30) return 'MEDIUM';
      if (score > 0) return 'LOW';
      return 'CLEAN';
    }

    assert.equal(computeRiskTier(95), 'CRITICAL');
    assert.equal(computeRiskTier(65), 'HIGH');
    assert.equal(computeRiskTier(45), 'MEDIUM');
    assert.equal(computeRiskTier(15), 'LOW');
    assert.equal(computeRiskTier(0), 'CLEAN');
  });

  await t.test('Verification badge mapping', () => {
    function getVerificationBadge(status) {
      switch (status) {
        case 'verified':
          return { label: '🛡️ Verified', variant: 'success' };
        case 'refuted':
          return { label: '❌ Refuted', variant: 'danger' };
        case 'pending':
          return { label: '⏳ Pending', variant: 'warning' };
        case 'unconfirmed':
        default:
          return { label: '⚠️ Unconfirmed', variant: 'muted' };
      }
    }

    assert.equal(getVerificationBadge('verified').label, '🛡️ Verified');
    assert.equal(getVerificationBadge('refuted').variant, 'danger');
    assert.equal(getVerificationBadge('pending').label, '⏳ Pending');
    assert.equal(getVerificationBadge(undefined).label, '⚠️ Unconfirmed');
  });

  await t.test('Failed job handling and error extraction', () => {
    function parseJobError(jobResponse) {
      if (jobResponse.status === 'failed') {
        return {
          isError: true,
          error: jobResponse.error || 'Job failed without explicit error message',
          canRetry: jobResponse.can_retry !== false
        };
      }
      return { isError: false };
    }

    const failed = parseJobError({ status: 'failed', error: 'Timeout in sandbox' });
    assert.equal(failed.isError, true);
    assert.equal(failed.error, 'Timeout in sandbox');
    assert.equal(failed.canRetry, true);

    const normal = parseJobError({ status: 'completed', result: [] });
    assert.equal(normal.isError, false);
  });

  await t.test('API error status mapping', () => {
    function mapApiError(status, data) {
      if (status === 401) {
        return 'Unauthorized: Invalid or missing authentication token.';
      }
      if (status === 429) {
        return 'Rate limit exceeded. Please wait before retrying.';
      }
      if (status >= 500) {
        return 'Internal Server Error. Backend is degraded or temporarily unavailable.';
      }
      return data?.message || data?.error || 'Unexpected error occurred.';
    }

    assert.match(mapApiError(401, null), /Unauthorized/);
    assert.match(mapApiError(429, null), /Rate limit/);
    assert.match(mapApiError(503, null), /Internal Server Error/);
    assert.equal(mapApiError(400, { message: 'Invalid payload' }), 'Invalid payload');
  });

  await t.test('Token handling and redaction', () => {
    function getAuthHeaders(token) {
      if (!token) return {};
      return { Authorization: `Bearer ${token.trim()}` };
    }

    function maskToken(token) {
      if (!token || token.length < 8) return '****';
      return `${token.slice(0, 4)}...${token.slice(-4)}`;
    }

    assert.deepEqual(getAuthHeaders(null), {});
    assert.deepEqual(getAuthHeaders('secret-jwt-123'), { Authorization: 'Bearer secret-jwt-123' });
    assert.equal(maskToken('ghp_1234567890abcdef'), 'ghp_...cdef');
    assert.equal(maskToken('short'), '****');
  });
});
