import * as vscode from 'vscode';
import { Vulnerability } from './client';
import { VERDICT_LABEL, verdictOf } from './verdict';

export class DiagnosticsManager {
	private diagnosticsCollection = vscode.languages.createDiagnosticCollection('sageArmor');
	private remediationMap = new Map<string, string>();
	private detailsMap = new Map<string, Vulnerability>();
	private fixRangeMap = new Map<string, vscode.Range>();

	createDiagnostics(vulnerabilities: Vulnerability[], uri: vscode.Uri): vscode.Diagnostic[] {
		this.remediationMap.clear();
		this.detailsMap.clear();
		this.fixRangeMap.clear();

		return vulnerabilities.map((vuln, idx) => {
			const isFileLevel = vuln.line === null;
			// If line is null, treat as file-level diagnostic without pinning to line 0 code span
			const range = isFileLevel
				? new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 0))
				: new vscode.Range(new vscode.Position(vuln.line as number, 0), new vscode.Position(vuln.line as number, 1000));

			const verificationLabel = `[${VERDICT_LABEL[verdictOf(vuln)] ?? 'Pending'}]`;

			const isValidatedPatch = vuln.patch_status === 'validated_patch' || vuln.validated_patch === true;
			const patchLabel = isValidatedPatch
				? '[Validated Patch]'
				: (vuln.remediation && vuln.remediation.trim() !== '')
				? '[Unvalidated Patch]'
				: '';

			const traceLabel = vuln.verified && vuln.dynamic_trace?.sink_reached
				? `[Exploit sink reached${vuln.dynamic_trace.sink_line ? ` at line ${vuln.dynamic_trace.sink_line}` : ''}]`
				: '';

			const prefixes = [
				isFileLevel ? '[File-level]' : '',
				verificationLabel,
				patchLabel,
				traceLabel,
			].filter(Boolean).join(' ');

			const severity = this.mapSeverity(vuln.severity);

			const diagnostic = new vscode.Diagnostic(
				range,
				`${prefixes} ${vuln.title}: ${vuln.description}`.trim(),
				severity
			);
			diagnostic.source = vuln.severity;

			const key = `${uri.toString()}#${vuln.finding_id || `${vuln.line ?? 'file'}:${idx}`}`;

			// Code for Quick Fix (includes key for lookup)
			diagnostic.code = `sage-armor-fix:${key}`;
			if (!isFileLevel && vuln.line !== null) {
				const endLine = vuln.endLine !== null ? vuln.endLine : vuln.line;
				const fixRange = new vscode.Range(
					new vscode.Position(vuln.line, Math.max(0, vuln.column || 0)),
					new vscode.Position(endLine, Math.max(0, vuln.endColumn || vuln.column || 0))
				);
				this.fixRangeMap.set(key, fixRange);
			}

			// Store remediation/details for Quick Fix + Hover
			this.remediationMap.set(key, vuln.remediation);
			this.detailsMap.set(key, vuln);

			return diagnostic;
		});
	}

	getRemediation(key: string): string {
		return this.remediationMap.get(key) || '';
	}

	getDetails(key: string): Vulnerability | undefined {
		return this.detailsMap.get(key);
	}

	getFixRange(key: string): vscode.Range | undefined {
		return this.fixRangeMap.get(key);
	}

	setDiagnostics(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]) {
		this.diagnosticsCollection.set(uri, diagnostics);
	}

	clearDiagnostics(uri?: vscode.Uri) {
		if (uri) {
			this.diagnosticsCollection.delete(uri);
		} else {
			this.diagnosticsCollection.clear();
		}
		this.remediationMap.clear();
		this.detailsMap.clear();
		this.fixRangeMap.clear();
	}

	dispose() {
		this.diagnosticsCollection.dispose();
		this.remediationMap.clear();
		this.detailsMap.clear();
		this.fixRangeMap.clear();
	}

	private mapSeverity(severity: string): vscode.DiagnosticSeverity {
		switch (severity.toLowerCase()) {
			case 'critical':
			case 'high':
				return vscode.DiagnosticSeverity.Error;
			case 'medium':
				return vscode.DiagnosticSeverity.Warning;
			case 'low':
				return vscode.DiagnosticSeverity.Information;
			default:
				return vscode.DiagnosticSeverity.Warning;
		}
	}
}
