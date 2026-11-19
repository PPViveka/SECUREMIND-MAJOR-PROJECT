export function normalizeRemediation(remediation: string, indentation: string): string {
	const lines = remediation.replace(/\r\n/g, '\n').split('\n');
	if (lines.length <= 1) {
		return remediation;
	}

	return lines
		.map((line, idx) => (idx === 0 || line.trim().length === 0 ? line : `${indentation}${line}`))
		.join('\n');
}

export function createDiffHunk(
	originalCode: string,
	replacementCode: string,
	startLine = 1,
	filePath = 'source.py'
): string {
	const originalLines = originalCode.replace(/\r\n/g, '\n').split('\n');
	const replacementLines = replacementCode.replace(/\r\n/g, '\n').split('\n');

	const header = `--- a/${filePath}\n+++ b/${filePath}\n@@ -${startLine},${originalLines.length} +${startLine},${replacementLines.length} @@\n`;
	const removed = originalLines.map((l) => `-${l}`).join('\n');
	const added = replacementLines.map((l) => `+${l}`).join('\n');

	return `${header}${removed}\n${added}\n`;
}

export function applyPatchPreservingContext(
	fullText: string,
	startLine: number,
	endLine: number,
	replacement: string
): string {
	const lines = fullText.replace(/\r\n/g, '\n').split('\n');
	const before = lines.slice(0, Math.max(0, startLine));
	const after = lines.slice(Math.min(lines.length, endLine + 1));
	return [...before, replacement, ...after].join('\n');
}
