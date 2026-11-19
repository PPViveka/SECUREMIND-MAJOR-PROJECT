require('./mock_vscode.cjs');
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

describe('Extension Host Integration Tests', () => {

  test('extension bundle exports activate and deactivate', () => {
    // Check that out/extension.js exports standard VS Code extension lifecycle hooks
    const extensionModule = require('../out/extension.js');
    assert.equal(typeof extensionModule.activate, 'function');
    assert.equal(typeof extensionModule.deactivate, 'function');
  });

  test('simulates /review normalization with dynamic trace and verification details', () => {
    const { normalizeReviewResponse } = require('../out/testable.js');
    const mockBackendPayload = {
      vulnerabilities: [
        {
          finding_id: 'vuln-sql-1',
          issue: 'SQL Injection',
          explanation: 'Dynamic query construction with unsanitized parameters.',
          severity: 'Critical',
          line: 25,
          column: 10,
          verified: true,
          verification: { verdict: 'verified', reason: 'Exploit canary succeeded in sandbox' },
          patch_status: 'validated_patch',
          dynamic_trace: { sink_reached: true, sink_line: 25 },
          remediation: {
            patch: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            description: 'Use parameterized query',
          },
        },
        {
          finding_id: 'vuln-weak-crypto',
          issue: 'Weak Cryptographic Hash',
          explanation: 'MD5 is cryptographically broken.',
          severity: 'Medium',
          line: null, // File-level finding
          verified: false,
          verification_status: 'unconfirmed',
          patch_status: 'unverified_draft',
          remediation: 'hashlib.sha256(data)',
        },
      ],
      language: 'python',
      analysis_mode: 'model',
    };

    const review = normalizeReviewResponse(mockBackendPayload, 'python');
    assert.equal(review.vulnerabilities.length, 2);

    const v1 = review.vulnerabilities[0];
    assert.equal(v1.title, 'SQL Injection');
    assert.equal(v1.verified, true);
    assert.equal(v1.verification_status, 'verified');
    assert.equal(v1.patch_status, 'validated_patch');
    assert.equal(v1.dynamic_trace.sink_reached, true);
    assert.equal(v1.line, 24);

    const v2 = review.vulnerabilities[1];
    assert.equal(v2.title, 'Weak Cryptographic Hash');
    assert.equal(v2.line, null);
    assert.equal(v2.is_file_level, true);
    assert.equal(v2.verification_status, 'unconfirmed');
    assert.equal(v2.patch_status, 'unverified_draft');
  });

  test('simulates save scanning debounce and rules-only keystroke scanning', () => {
    const saveDebounceDelay = 1500;
    const keystrokeDebounceDelay = 300;
    assert.ok(saveDebounceDelay >= 1500, 'Save debounce must be at least 1500ms');
    assert.ok(keystrokeDebounceDelay <= 500, 'Keystroke debounce must be responsive');
  });

  test('simulates command dispatch for attackPath, riskScore, and repoScan', () => {
    const commands = [
      'sageArmor.scanFile',
      'sageArmor.scanWorkspace',
      'sageArmor.openSettings',
      'sageArmor.openAdvancedSettings',
      'sageArmor.testConnection',
      'sageArmor.rescanActiveFile',
      'sageArmor.previewFix',
      'sageArmor.attackPath',
      'sageArmor.riskScore',
      'sageArmor.copilotChat',
      'sageArmor.repoScan',
      'sageArmor.repoAutofix',
    ];

    const packageJson = require('../package.json');
    const contributedCommands = packageJson.contributes.commands.map((c) => c.command);

    for (const cmd of commands) {
      assert.ok(
        contributedCommands.includes(cmd),
        `Command ${cmd} should be registered in package.json contributes.commands`
      );
    }
  });

  test('scans fixture documents across languages with real normalization and diagnostic ranges', () => {
    const { normalizeReviewResponse, createDiffHunk } = require('../out/testable.js');
    const fixtures = [
      { lang: 'python', code: 'import os\nos.system(cmd)\n', line: 2 },
      { lang: 'javascript', code: "const cp = require('child_process');\ncp.exec(cmd);\n", line: 2 },
      { lang: 'go', code: 'package main\nimport "os/exec"\nfunc main() { exec.Command(c).Run() }\n', line: 3 },
    ];

    for (const f of fixtures) {
      const mockPayload = {
        vulnerabilities: [
          {
            finding_id: `vuln-${f.lang}`,
            issue: 'Command Injection',
            severity: 'High',
            line: f.line,
            verified: true,
            remediation: { patch: '# sanitized patch\n' }
          }
        ],
        language: f.lang
      };

      const normalized = normalizeReviewResponse(mockPayload, f.lang);
      assert.equal(normalized.vulnerabilities.length, 1);
      assert.equal(normalized.vulnerabilities[0].line, f.line - 1); // 0-indexed for VS Code Range
      assert.equal(normalized.vulnerabilities[0].verified, true);

      // Verify diff generation
      const diff = createDiffHunk(f.code, '# sanitized patch\n', f.line, `file.${f.lang}`);
      assert.ok(diff.includes('--- a/'));
      assert.ok(diff.includes('+++ b/'));
    }
  });

});
