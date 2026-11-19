import type { Vulnerability } from './client';
import * as path from 'path';

export interface ScanSummary {
	total: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
}

const SUPPORTED_EXTENSIONS: Record<string, string> = {
	'.py': 'python',
	'.js': 'javascript',
	'.jsx': 'javascript',
	'.ts': 'typescript',
	'.tsx': 'typescript',
	'.java': 'java',
	'.go': 'go',
	'.cpp': 'cpp',
	'.cc': 'cpp',
	'.cxx': 'cpp',
	'.c': 'c',
	'.h': 'c',
	'.hpp': 'cpp',
	'.cs': 'csharp',
	'.rb': 'ruby',
	'.php': 'php',
	'.swift': 'swift',
	'.kt': 'kotlin',
	'.rs': 'rust',
	'.sql': 'sql',
};

const SUPPORTED_LANGUAGES = new Set([
	'python',
	'javascript',
	'typescript',
	'javascriptreact',
	'typescriptreact',
	'java',
	'go',
	'cpp',
	'c',
	'csharp',
	'ruby',
	'php',
	'swift',
	'kotlin',
	'rust',
	'sql',
]);

export function isSupportedLanguage(lang: string): boolean {
	return SUPPORTED_LANGUAGES.has(lang.toLowerCase());
}

export function isSupportedExtension(ext: string): boolean {
	const normalized = ext.startsWith('.') ? ext.toLowerCase() : `.${ext.toLowerCase()}`;
	return Boolean(SUPPORTED_EXTENSIONS[normalized]);
}

export function getLanguageForExtension(filePath: string): string {
	const ext = path.extname(filePath).toLowerCase();
	return SUPPORTED_EXTENSIONS[ext] || 'plaintext';
}

export function filterBySeverity(
	vulnerabilities: Vulnerability[],
	severityFilter: string[],
	showRefuted = false
): Vulnerability[] {
	return vulnerabilities.filter((v) => {
		if (!showRefuted && (v.verification_status === 'refuted' || v.verification?.verdict === 'refuted')) {
			return false;
		}
		return severityFilter.map((s) => s.toLowerCase()).includes(v.severity.toLowerCase());
	});
}

export function summarizeVulnerabilities(vulnerabilities: Vulnerability[]): ScanSummary {
	const summary: ScanSummary = {
		total: vulnerabilities.length,
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
	};

	for (const vuln of vulnerabilities) {
		switch (vuln.severity) {
			case 'Critical':
				summary.critical += 1;
				break;
			case 'High':
				summary.high += 1;
				break;
			case 'Medium':
				summary.medium += 1;
				break;
			case 'Low':
				summary.low += 1;
				break;
			default:
				summary.low += 1;
		}
	}

	return summary;
}
