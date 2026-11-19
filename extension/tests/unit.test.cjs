const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  normalizeReviewResponse,
  mapBackendError,
  filterBySeverity,
  summarizeVulnerabilities,
  isSupportedLanguage,
  isSupportedExtension,
  getLanguageForExtension,
  normalizeRemediation,
  createDiffHunk,
  applyPatchPreservingContext,
} = require('../out/testable.js');

describe('SageArmor Extension Unit Tests', () => {

  describe('Review Response Normalization', () => {
    test('normalizes standard vulnerability payload', () => {
      const rawData = {
        vulnerabilities: [
          {
            finding_id: 'vuln-1',
            title: 'SQL Injection',
            severity: 'High',
            line: 12,
            endLine: 14,
            column: 5,
            endColumn: 20,
            remediation: 'cursor.execute("SELECT ...", (id,))',
            verified: true,
            patch_status: 'validated_patch',
          },
        ],
        language: 'python',
        analysis_mode: 'model',
      };

      const result = normalizeReviewResponse(rawData, 'python');
      assert.equal(result.vulnerabilities.length, 1);
      const v = result.vulnerabilities[0];
      assert.equal(v.finding_id, 'vuln-1');
      assert.equal(v.title, 'SQL Injection');
      assert.equal(v.severity, 'High');
      assert.equal(v.line, 11); // 1-indexed to 0-indexed
      assert.equal(v.endLine, 13);
      assert.equal(v.verified, true);
      assert.equal(v.verification_status, 'verified');
      assert.equal(v.patch_status, 'validated_patch');
      assert.equal(v.validated_patch, true);
      assert.equal(v.is_file_level, false);
    });

    test('handles null or missing line numbers cleanly without pinning to line 0', () => {
      const rawData = {
        vulnerabilities: [
          {
            finding_id: 'vuln-missing-line',
            title: 'Hardcoded credentials in config',
            severity: 'Critical',
            // No line, range, or column
          },
        ],
      };

      const result = normalizeReviewResponse(rawData, 'python');
      assert.equal(result.vulnerabilities.length, 1);
      const v = result.vulnerabilities[0];
      assert.equal(v.line, null, 'Line should be null when not provided');
      assert.equal(v.endLine, null);
      assert.equal(v.is_file_level, true);
    });

    test('distinguishes validated patch from unverified draft', () => {
      const rawData = {
        vulnerabilities: [
          {
            title: 'Validated issue',
            remediation: 'safe_fix()',
            patch_status: 'validated_patch',
          },
          {
            title: 'Unverified issue',
            remediation: 'draft_fix()',
            patch_status: 'unverified_draft',
          },
          {
            title: 'No fix issue',
          },
        ],
      };

      const result = normalizeReviewResponse(rawData, 'python');
      assert.equal(result.vulnerabilities[0].patch_status, 'validated_patch');
      assert.equal(result.vulnerabilities[0].validated_patch, true);
      assert.equal(result.vulnerabilities[1].patch_status, 'unverified_draft');
      assert.equal(result.vulnerabilities[1].validated_patch, false);
      assert.equal(result.vulnerabilities[2].patch_status, 'none');
    });
  });

  describe('Backend Error Mapping', () => {
    test('maps 429 rate limit error', () => {
      const err = { response: { status: 429, data: { retry_after_seconds: 10 } } };
      const msg = mapBackendError(err, 'http://localhost:6060');
      assert.match(msg, /Quota exceeded/);
      assert.match(msg, /10 seconds/);
    });

    test('maps 401 unauthorized error', () => {
      const err = { response: { status: 401 } };
      const msg = mapBackendError(err, 'http://localhost:6060');
      assert.match(msg, /Invalid API key/);
    });

    test('maps 500 server error', () => {
      const err = { response: { status: 500 } };
      const msg = mapBackendError(err, 'http://localhost:6060');
      assert.match(msg, /Backend server error/);
    });

    test('maps ECONNREFUSED', () => {
      const err = { code: 'ECONNREFUSED' };
      const msg = mapBackendError(err, 'http://localhost:6060');
      assert.match(msg, /Cannot connect to backend at http:\/\/localhost:6060/);
    });

    test('maps ECONNABORTED timeout', () => {
      const err = { code: 'ECONNABORTED' };
      const msg = mapBackendError(err, 'http://localhost:6060');
      assert.match(msg, /Backend request timed out/);
    });
  });

  describe('Severity Filtering and Summaries', () => {
    const vulns = [
      { severity: 'Critical', title: 'C1' },
      { severity: 'High', title: 'H1' },
      { severity: 'Medium', title: 'M1' },
      { severity: 'Low', title: 'L1' },
      { severity: 'High', title: 'H2', verification_status: 'refuted' },
    ];

    test('filters by selected severity levels', () => {
      const filtered = filterBySeverity(vulns, ['Critical', 'High']);
      assert.equal(filtered.length, 2); // H2 refuted excluded by default
      assert.equal(filtered[0].title, 'C1');
      assert.equal(filtered[1].title, 'H1');
    });

    test('includes refuted findings when showRefuted is true', () => {
      const filtered = filterBySeverity(vulns, ['Critical', 'High'], true);
      assert.equal(filtered.length, 3);
      assert.equal(filtered[2].title, 'H2');
    });

    test('summarizes counts across severity categories', () => {
      const summary = summarizeVulnerabilities(vulns);
      assert.equal(summary.total, 5);
      assert.equal(summary.critical, 1);
      assert.equal(summary.high, 2);
      assert.equal(summary.medium, 1);
      assert.equal(summary.low, 1);
    });
  });

  describe('File-Extension and Language Detection', () => {
    test('identifies supported extensions', () => {
      assert.equal(isSupportedExtension('.py'), true);
      assert.equal(isSupportedExtension('.ts'), true);
      assert.equal(isSupportedExtension('.js'), true);
      assert.equal(isSupportedExtension('.go'), true);
      assert.equal(isSupportedExtension('.rs'), true);
      assert.equal(isSupportedExtension('.java'), true);
      assert.equal(isSupportedExtension('.txt'), false);
      assert.equal(isSupportedExtension('.md'), false);
    });

    test('resolves language from file path extension', () => {
      assert.equal(getLanguageForExtension('app/main.py'), 'python');
      assert.equal(getLanguageForExtension('frontend/index.tsx'), 'typescript');
      assert.equal(getLanguageForExtension('service/main.go'), 'go');
      assert.equal(getLanguageForExtension('unknown.xyz'), 'plaintext');
    });

    test('checks supported language ID', () => {
      assert.equal(isSupportedLanguage('python'), true);
      assert.equal(isSupportedLanguage('javascript'), true);
      assert.equal(isSupportedLanguage('rust'), true);
      assert.equal(isSupportedLanguage('sql'), true);
      assert.equal(isSupportedLanguage('cobol'), false);
    });
  });

  describe('Fix and Diff Utilities', () => {
    test('normalizes indentation for multi-line remediation', () => {
      const remediation = 'def fix():\n    return 42';
      const normalized = normalizeRemediation(remediation, '    ');
      const lines = normalized.split('\n');
      assert.equal(lines[0], 'def fix():');
      assert.equal(lines[1], '        return 42');
    });

    test('generates valid unified diff hunk', () => {
      const hunk = createDiffHunk('bad_code()', 'good_code()', 10, 'app.py');
      assert.match(hunk, /--- a\/app\.py/);
      assert.match(hunk, /\+\+\+ b\/app\.py/);
      assert.match(hunk, /@@ -10,1 \+10,1 @@/);
      assert.match(hunk, /-bad_code\(\)/);
      assert.match(hunk, /\+good_code\(\)/);
    });

    test('applies patch preserving surrounding code lines', () => {
      const fullText = 'line1\nline2\nline3\nline4';
      const patched = applyPatchPreservingContext(fullText, 1, 2, 'replaced_line2_and_3');
      const lines = patched.split('\n');
      assert.equal(lines[0], 'line1');
      assert.equal(lines[1], 'replaced_line2_and_3');
      assert.equal(lines[2], 'line4');
    });
  });

});
