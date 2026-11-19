import * as vscode from 'vscode';

export class SettingsManager {
	private config = vscode.workspace.getConfiguration('sageArmor');

	get backendUrl(): string {
		return this.config.get('backendUrl', 'http://localhost:6060');
	}

	get apiKey(): string {
		return this.config.get('apiKey', '');
	}

	get scanOnSave(): boolean {
		return this.config.get('scanOnSave', true);
	}

	get scanOnKeystroke(): boolean {
		return this.config.get('scanOnKeystroke', false);
	}

	get severityFilter(): string[] {
		return this.config.get('severityFilter', ['Critical', 'High', 'Medium']);
	}

	get supportedLanguages(): string[] {
		return this.config.get('supportedLanguages', ['python', 'javascript', 'typescript']);
	}

	get scanMode(): 'rules-only' | 'balanced' | 'thorough' {
		return this.config.get('scanMode', 'balanced');
	}

	get dailyBudget(): number {
		return this.config.get('dailyBudget', 100);
	}

	get provider(): string {
		return this.config.get('provider', 'Amazon Bedrock');
	}

	get sandboxPolicy(): 'subprocess' | 'docker' | 'mock' | 'strict' {
		return this.config.get('sandboxPolicy', 'subprocess');
	}

	get showRefuted(): boolean {
		return this.config.get('showRefuted', false);
	}

	get privacyNotice(): string {
		return this.config.get('privacyNotice', 'Code is sent to configured backend URL. Local fallback or API key depends on provider configuration.');
	}

	async setApiKey(key: string) {
		await this.config.update('apiKey', key, vscode.ConfigurationTarget.Global);
	}

	async setBackendUrl(url: string) {
		await this.config.update('backendUrl', url, vscode.ConfigurationTarget.Workspace);
		this.refresh();
	}

	async setScanOnSave(enabled: boolean) {
		await this.config.update('scanOnSave', enabled, vscode.ConfigurationTarget.Workspace);
		this.refresh();
	}

	async setScanOnKeystroke(enabled: boolean) {
		await this.config.update('scanOnKeystroke', enabled, vscode.ConfigurationTarget.Workspace);
		this.refresh();
	}

	async setSeverityFilter(levels: string[]) {
		await this.config.update('severityFilter', levels, vscode.ConfigurationTarget.Workspace);
		this.refresh();
	}

	async setScanMode(mode: 'rules-only' | 'balanced' | 'thorough') {
		await this.config.update('scanMode', mode, vscode.ConfigurationTarget.Workspace);
		this.refresh();
	}

	async setDailyBudget(budget: number) {
		await this.config.update('dailyBudget', Math.max(0, budget), vscode.ConfigurationTarget.Workspace);
		this.refresh();
	}

	refresh() {
		this.config = vscode.workspace.getConfiguration('sageArmor');
	}

	validateSettings(): string | null {
		if (!this.backendUrl) {
			return 'Backend URL not configured';
		}
		if (!this.backendUrl.startsWith('http')) {
			return 'Backend URL must start with http:// or https://';
		}
		return null;
	}
}
