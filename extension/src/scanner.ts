import * as vscode from 'vscode';
import { ExtensionClient } from './client';
import { DiagnosticsManager } from './diagnostics';
import { SettingsManager } from './settings';
import { filterBySeverity } from './scanUtils';
import * as path from 'path';

export class ScannerManager {
	private client: ExtensionClient;
	private diagnosticsManager: DiagnosticsManager;
	private settingsManager: SettingsManager;
	private scanInProgress = false;
	private debounceTimer: NodeJS.Timeout | null = null;
	private debounceResolve: (() => void) | null = null;

	constructor(
		client: ExtensionClient,
		diagnosticsManager: DiagnosticsManager,
		settingsManager: SettingsManager
	) {
		this.client = client;
		this.diagnosticsManager = diagnosticsManager;
		this.settingsManager = settingsManager;
	}

	isSupportedLanguage(languageId: string): boolean {
		const supported = {
			python: 'python',
			javascript: 'javascript',
			typescript: 'typescript',
			javascriptreact: 'javascript',
			typescriptreact: 'typescript',
			java: 'java',
			go: 'go',
			cpp: 'cpp',
			c: 'c',
			csharp: 'csharp',
			ruby: 'ruby',
			php: 'php',
			swift: 'swift',
			kotlin: 'kotlin',
			rust: 'rust',
			sql: 'sql',
		};

		return Object.keys(supported).includes(languageId);
	}

	isSupportedDocument(document: vscode.TextDocument): boolean {
		if (this.isSupportedLanguage(document.languageId)) {
			return true;
		}

		const extensionLanguage: Record<string, string> = {
			'.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
			'.ts': 'typescript', '.tsx': 'typescript', '.java': 'java',
			'.go': 'go', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
			'.c': 'c', '.h': 'c', '.hpp': 'cpp', '.cs': 'csharp',
			'.rb': 'ruby', '.php': 'php', '.swift': 'swift', '.kt': 'kotlin',
			'.rs': 'rust', '.sql': 'sql',
		};

		return Boolean(extensionLanguage[path.extname(document.fileName).toLowerCase()]);
	}

	getLanguageForId(languageId: string): string {
		const mapping: Record<string, string> = {
			python: 'python',
			javascript: 'javascript',
			typescript: 'typescript',
			javascriptreact: 'javascript',
			typescriptreact: 'typescript',
			java: 'java',
			go: 'go',
			cpp: 'cpp',
			c: 'c',
			csharp: 'csharp',
			ruby: 'ruby',
			php: 'php',
			swift: 'swift',
			kotlin: 'kotlin',
			rust: 'rust',
			sql: 'sql',
		};

		return mapping[languageId] || languageId;
	}

	getLanguageForDocument(document: vscode.TextDocument): string {
		if (this.isSupportedLanguage(document.languageId)) {
			return this.getLanguageForId(document.languageId);
		}

		const extensionLanguage: Record<string, string> = {
			'.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
			'.ts': 'typescript', '.tsx': 'typescript', '.java': 'java',
			'.go': 'go', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
			'.c': 'c', '.h': 'c', '.hpp': 'cpp', '.cs': 'csharp',
			'.rb': 'ruby', '.php': 'php', '.swift': 'swift', '.kt': 'kotlin',
			'.rs': 'rust', '.sql': 'sql',
		};

		return extensionLanguage[path.extname(document.fileName).toLowerCase()] || document.languageId;
	}

	async scanFile(
		document: vscode.TextDocument,
		showNotification = false,
		mode: 'rules-only' | 'model' | 'default' = 'default'
	): Promise<void> {
		if (this.scanInProgress) {
			return;
		}

		// Debounce if keystroke scanning is enabled (at least 1.5s for save scans)
		if (this.debounceTimer) {
			clearTimeout(this.debounceTimer);
			if (this.debounceResolve) {
				this.debounceResolve();
				this.debounceResolve = null;
			}
		}

		const debounceDelayMs = mode === 'rules-only' ? 300 : 1500;

		await new Promise<void>((resolve) => {
			this.debounceResolve = resolve;
			this.debounceTimer = setTimeout(async () => {
				try {
					await this._performScan(document, showNotification, mode);
				} finally {
					if (this.debounceResolve) {
						this.debounceResolve();
						this.debounceResolve = null;
					}
					this.debounceTimer = null;
				}
			}, debounceDelayMs);
		});
	}

	async scanWorkspace(): Promise<void> {
		if (!vscode.workspace.workspaceFolders) {
			vscode.window.showWarningMessage('No workspace open');
			return;
		}

		const pattern = '{**/*.py,**/*.js,**/*.ts,**/*.jsx,**/*.tsx,**/*.java,**/*.go,**/*.cpp,**/*.c,**/*.cs,**/*.rb,**/*.php,**/*.swift,**/*.kt,**/*.rs,**/*.sql}';
		const files = await vscode.workspace.findFiles(pattern);

		if (files.length === 0) {
			vscode.window.showInformationMessage('No supported files found in workspace');
			return;
		}

		// Concurrency bounds and cost estimate
		const estimatedTokens = files.length * 200;
		const estimatedCostUsd = (estimatedTokens * 0.000002).toFixed(4);
		vscode.window.showInformationMessage(
			`Workspace scan: ${files.length} files queued (est. ~${estimatedTokens} tokens, ~$${estimatedCostUsd} USD)`
		);

		let scannedCount = 0;
		let errorCount = 0;
		let issueCount = 0;
		const CONCURRENCY_LIMIT = 3;

		await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: 'Sage Armor: Scanning workspace',
				cancellable: false,
			},
			async (progress) => {
				for (let i = 0; i < files.length; i += CONCURRENCY_LIMIT) {
					const chunk = files.slice(i, i + CONCURRENCY_LIMIT);
					await Promise.all(
						chunk.map(async (fileUri) => {
							try {
								const document = await vscode.workspace.openTextDocument(fileUri);
								const issuesInFile = await this._performScan(document, false, 'default');
								scannedCount++;
								issueCount += issuesInFile;
							} catch (error) {
								errorCount++;
								console.error(`Error scanning ${fileUri}:`, error);
							}
						})
					);

					const increment = Math.round((chunk.length / files.length) * 100);
					progress.report({
						increment,
						message: `${Math.min(i + CONCURRENCY_LIMIT, files.length)}/${files.length} files scanned`,
					});
				}
			}
		);

		vscode.window.showInformationMessage(
			`Scan complete: ${scannedCount} files scanned, ${issueCount} issue(s) found${errorCount > 0 ? `, ${errorCount} errors` : ''}`
		);
	}

	private async _performScan(
		document: vscode.TextDocument,
		showNotification = true,
		mode: 'rules-only' | 'model' | 'default' = 'default'
	): Promise<number> {
		if (this.scanInProgress) {
			return 0;
		}

		this.scanInProgress = true;

		try {
			const code = document.getText();
			const language = this.getLanguageForDocument(document);

			const scanMode = mode === 'rules-only' ? 'rules-only' : this.settingsManager.scanMode;
			const result = await this.client.reviewCode(code, language, scanMode);
			const vulnerabilities = Array.isArray(result.vulnerabilities)
				? result.vulnerabilities
				: [];

			// Filter by severity
			const filtered = filterBySeverity(
				vulnerabilities,
				this.settingsManager.severityFilter,
				this.settingsManager.showRefuted
			);

			// Create and set diagnostics
			const diagnostics = this.diagnosticsManager.createDiagnostics(filtered, document.uri);
			this.diagnosticsManager.setDiagnostics(document.uri, diagnostics);

			if (showNotification && filtered.length > 0) {
				vscode.window.showWarningMessage(
					`Found ${filtered.length} security issue(s) in ${document.fileName}`
				);
			}

			return filtered.length;
		} catch (error: any) {
			this.diagnosticsManager.clearDiagnostics(document.uri);

			const errorMsg = error.message || 'Unknown error';
			console.error('Scan error:', errorMsg);

			if (showNotification) {
				vscode.window.showErrorMessage(`Sage Armor scan failed: ${errorMsg}`);
			}

			return 0;
		} finally {
			this.scanInProgress = false;
		}
	}
}
