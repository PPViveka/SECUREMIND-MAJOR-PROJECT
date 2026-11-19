import * as vscode from 'vscode';
import { ExtensionClient, Vulnerability } from './client';
import { ScannerManager } from './scanner';
import { DiagnosticsManager } from './diagnostics';
import { SettingsManager } from './settings';
import { SageArmorSidebarProvider } from './sidebar';
import { AdvancedSettingsPanel } from './settingsPanel';
import { normalizeRemediation, createDiffHunk } from './fixUtils';
import { VERDICT_LABEL, verdictOf } from './verdict';
import { buildFixFinding, describeGatedFix, pickGatedFix, repoFindingsForAutofix, toFindingPatchStatus } from './verifiedFix';

let diagnosticsManager: DiagnosticsManager;
let scannerManager: ScannerManager;
let client: ExtensionClient;
let settingsManager: SettingsManager;
let sidebarProvider: SageArmorSidebarProvider;
let advancedSettingsPanel: AdvancedSettingsPanel;

function adaptRemediationForLanguage(title: string, remediation: string, languageId: string): string {
	const t = title.toLowerCase();
	const jsLike = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
	const cLike = ['java', 'go', 'cpp', 'c', 'csharp', 'php', 'swift', 'kotlin', 'rust'];
	const pythonLike = ['python'];
	const rubyLike = ['ruby'];
	const sqlLike = ['sql'];

	const isJs = jsLike.includes(languageId);
	const isPython = pythonLike.includes(languageId);
	const isCLike = cLike.includes(languageId);
	const isRuby = rubyLike.includes(languageId);
	const isSql = sqlLike.includes(languageId);

	if (t.includes('path traversal')) {
		if (isJs) {
			return 'const path = require("path");\nconst safeBaseDir = "/app/data";\nconst safePath = path.resolve(safeBaseDir, requestedFile);\nif (!safePath.startsWith(safeBaseDir + path.sep)) {\n  throw new Error("Invalid path");\n}';
		}
		if (isPython) {
			return 'safe_path = os.path.normpath(os.path.join(base_dir, user_file))\nif not safe_path.startswith(base_dir):\n    raise ValueError("Invalid path")';
		}
		if (isRuby) {
			return 'safe_path = File.expand_path(File.join(base_dir, user_file))\nraise "Invalid path" unless safe_path.start_with?(File.expand_path(base_dir) + File::SEPARATOR)';
		}
		if (isCLike) {
			return '// Validate canonical path stays under base directory before reading file.';
		}
	}

	if (t.includes('weak cryptographic')) {
		if (isJs) {
			return 'const crypto = require("crypto");\nconst strongHash = crypto.createHash("sha256").update(req.body.password).digest("hex");';
		}
		if (isPython) {
			return 'import hashlib\nhash_obj = hashlib.sha256(password.encode())';
		}
		if (isRuby) {
			return 'require "digest"\npassword_hash = Digest::SHA256.hexdigest(password)';
		}
		if (isCLike) {
			return '// Replace MD5/SHA1 with SHA-256 or stronger using your language crypto library.';
		}
	}

	if (t.includes('authentication') || t.includes('authorization bypass')) {
		if (isJs) {
			return 'function checkAdmin(req, res, next) {\n  const isAdmin = req.user && req.user.role === "admin";\n  if (!isAdmin) {\n    return res.status(403).send("Forbidden");\n  }\n  return next();\n}';
		}
		if (isPython) {
			return '@require_auth\ndef secure_endpoint(request):\n    return {"ok": True}';
		}
		if (isRuby) {
			return 'before_action :require_admin\ndef require_admin\n  head :forbidden unless current_user&.admin?\nend';
		}
		if (isCLike) {
			return '// Enforce role-based authorization middleware before entering handler.';
		}
	}

	if (t.includes('cors')) {
		if (isJs) {
			return 'app.use(cors({\n  origin: ["https://app.example.com"],\n  credentials: true,\n}));';
		}
		if (isPython) {
			return 'CORS(app, resources={r"/*": {"origins": ["https://app.example.com"]}}, supports_credentials=True)';
		}
		if (isRuby) {
			return 'config.middleware.insert_before 0, Rack::Cors do\n  allow do\n    origins "https://app.example.com"\n    resource "*", headers: :any, methods: %i[get post], credentials: true\n  end\nend';
		}
		if (isCLike) {
			return '// Replace wildcard CORS origin with an explicit allowlist domain.';
		}
	}

	if (t.includes('open redirect')) {
		if (isJs) {
			return 'app.get("/go", (req, res) => {\n  const nextUrl = String(req.query.next || "/");\n  if (!nextUrl.startsWith("/") || nextUrl.startsWith("//") || nextUrl.includes("://")) {\n    return res.status(400).send("Invalid redirect target");\n  }\n  return res.redirect(nextUrl);\n});';
		}
		if (isPython) {
			return 'next_url = request.args.get("next", "/")\nif not next_url.startswith("/") or "//" in next_url:\n    raise ValueError("Invalid redirect")\nreturn redirect(next_url)';
		}
		if (isRuby) {
			return 'next_url = params[:next].to_s\nreturn head :bad_request unless next_url.start_with?("/") && !next_url.start_with?("//")\nredirect_to next_url';
		}
		if (isCLike) {
			return '// Validate redirect target against a relative-path or allowlist policy before redirecting.';
		}
	}

	if (t.includes('missing input validation')) {
		if (isJs) {
			return 'const value = req.body.displayName;\nif (typeof value !== "string" || value.length < 1 || value.length > 80) {\n  return res.status(400).send("Invalid input");\n}\nres.send(value);';
		}
		if (isPython) {
			return 'value = request.json.get("displayName", "")\nif not isinstance(value, str) or not (1 <= len(value) <= 80):\n    raise ValueError("Invalid input")';
		}
		if (isRuby) {
			return 'value = params[:displayName].to_s\nraise ArgumentError, "Invalid input" unless (1..80).cover?(value.length)';
		}
		if (isCLike) {
			return '// Validate user input for type, length, and format before use.';
		}
	}

	if (t.includes('ssrf') || t.includes('server-side request forgery')) {
		if (isJs) {
			return 'const { URL } = require("url");\nconst allowedHosts = new Set(["api.example.com"]);\nconst target = new URL(req.body.url);\nif (!allowedHosts.has(target.hostname)) {\n  throw new Error("Blocked URL");\n}\naxios.get(target.toString());';
		}
		if (isPython) {
			return 'from urllib.parse import urlparse\nparsed = urlparse(user_url)\nif parsed.hostname not in {"api.example.com"}:\n    raise ValueError("Blocked URL")';
		}
		if (isRuby) {
			return 'uri = URI.parse(user_url)\nallowed = ["api.example.com"]\nraise "Blocked URL" unless allowed.include?(uri.host)';
		}
		if (isCLike) {
			return '// Parse URL and enforce hostname allowlist before outbound requests.';
		}
	}

	if (t.includes('prototype pollution')) {
		if (isJs) {
			return 'const safe = Object.create(null);\nfor (const [k, v] of Object.entries(req.body || {})) {\n  if (k === "__proto__" || k === "constructor" || k === "prototype") continue;\n  safe[k] = v;\n}';
		}
		if (isPython || isRuby || isCLike || isSql) {
			return '// Reject dangerous keys like __proto__/constructor/prototype when merging untrusted objects.';
		}
	}

	if (t.includes('redos') || t.includes('regular expression denial of service')) {
		if (isJs) {
			return 'const allowedPattern = /^[a-z0-9_-]{1,32}$/i;\nconst userPattern = req.query.pattern;\nif (!allowedPattern.test(userPattern)) {\n  throw new Error("Invalid pattern");\n}\nconst pattern = new RegExp(userPattern);';
		}
		if (isPython) {
			return 'if not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", user_pattern):\n    raise ValueError("Invalid pattern")';
		}
		if (isRuby) {
			return 'raise "Invalid pattern" unless user_pattern.match?(/^[a-z0-9_-]{1,32}$/i)';
		}
		if (isCLike) {
			return '// Validate regex pattern length/charset before compiling dynamic regex.';
		}
	}

	if (t.includes('unsafe dynamic code execution') || t.includes('insecure deserialization')) {
		if (isJs) {
			return 'const allowedActions = { ping: () => "pong" };\nconst action = req.body.script;\nif (!allowedActions[action]) {\n  throw new Error("Invalid action");\n}\nallowedActions[action]();';
		}
		if (isPython) {
			return 'allowed_actions = {"ping": lambda: "pong"}\naction = payload.get("action")\nif action not in allowed_actions:\n    raise ValueError("Invalid action")\nallowed_actions[action]()';
		}
		if (isRuby) {
			return 'allowed = {"ping" => -> { "pong" }}\naction = params[:action].to_s\nraise "Invalid action" unless allowed.key?(action)\nallowed[action].call';
		}
		if (isCLike) {
			return '// Replace eval/dynamic execution with explicit allowlisted operations.';
		}
	}

	if (t.includes('sql injection')) {
		if (isJs) {
			return 'db.query("SELECT * FROM users WHERE id = ?", [userId]);';
		}
		if (isPython) {
			return 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))';
		}
		if (isRuby) {
			return 'User.where("id = ?", user_id)';
		}
		if (isSql || isCLike) {
			return '// Use parameterized queries / prepared statements instead of string concatenation.';
		}
	}

	if (t.includes('hardcoded secret') || t.includes('credential')) {
		if (isJs) {
			return 'const apiKey = process.env.API_KEY;\nif (!apiKey) {\n  throw new Error("Missing API_KEY env var");\n}';
		}
		if (isPython) {
			return 'api_key = os.getenv("API_KEY")\nif not api_key:\n    raise ValueError("Missing API_KEY env var")';
		}
		if (isRuby) {
			return 'api_key = ENV.fetch("API_KEY")';
		}
		if (isCLike || isSql) {
			return '// Load secrets from environment variables or secret manager, never hardcode in source.';
		}
	}

	if (t.includes('xss') || t.includes('cross-site scripting')) {
		if (isJs) {
			return 'const escape = require("escape-html");\nres.send("<h1>Results for: " + escape(userInput) + "</h1>");';
		}
		if (isPython) {
			return 'from markupsafe import escape\nreturn f"<h1>Results for: {escape(user_input)}</h1>"';
		}
		if (isRuby) {
			return 'safe_text = ERB::Util.html_escape(user_input)\nrender html: "<h1>Results for: #{safe_text}</h1>".html_safe';
		}
		if (isCLike || isSql) {
			return '// HTML-escape untrusted output before rendering it in the response.';
		}
	}

	return remediation;
}

export function activate(context: vscode.ExtensionContext) {
	console.log('Sage Armor Scanner activated');

	// Initialize managers
	settingsManager = new SettingsManager();
	client = new ExtensionClient(settingsManager);
	diagnosticsManager = new DiagnosticsManager();
	scannerManager = new ScannerManager(client, diagnosticsManager, settingsManager);
	sidebarProvider = new SageArmorSidebarProvider();
	advancedSettingsPanel = new AdvancedSettingsPanel(settingsManager, client);

	// Create status bar item
	const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
	statusBar.text = `🛡️ Sage Armor (${settingsManager.provider}): Ready`;
	statusBar.show();

	const sidebarView = vscode.window.createTreeView('sageArmorPanel', {
		treeDataProvider: sidebarProvider,
	});

	const refreshSidebarAndStatus = () => {
		sidebarProvider.refresh();
		const summary = sidebarProvider.getSummary();
		statusBar.text = summary.total > 0
			? `🛡️ Sage Armor (${settingsManager.provider}): ${summary.total} issue(s)`
			: `🛡️ Sage Armor (${settingsManager.provider}): Ready`;
	};

	// Register Quick Fix action provider
	const codeActionProvider = vscode.languages.registerCodeActionsProvider(
		[
			'python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
			'java', 'go', 'cpp', 'c', 'csharp', 'ruby', 'php', 'swift', 'kotlin', 'rust', 'sql'
		],
		new SageArmorCodeActionProvider(diagnosticsManager),
		{ providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
	);

	// Register hover provider for better markdown rendering
	const hoverProvider = vscode.languages.registerHoverProvider(
		[
			'python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
			'java', 'go', 'cpp', 'c', 'csharp', 'ruby', 'php', 'swift', 'kotlin', 'rust', 'sql'
		],
		{
			provideHover(document, position, _token) {
				const diags = vscode.languages.getDiagnostics(document.uri);
				const diagnostic = diags.find(
					(d) =>
						d.range.start.line === position.line &&
						typeof d.code === 'string' &&
						d.code.startsWith('sage-armor-fix:')
				);

				if (diagnostic && typeof diagnostic.code === 'string') {
					const key = diagnostic.code.replace('sage-armor-fix:', '');
					const rawRemediation = diagnosticsManager.getRemediation(key);
					const details = diagnosticsManager.getDetails(key);
					const title = details?.title || diagnostic.message.split(':')[0] || 'Security Issue';
					const remediation = adaptRemediationForLanguage(title, rawRemediation, document.languageId);

					if (!remediation) {
						return null;
					}

					const verdictBadge = details ? (VERDICT_LABEL[verdictOf(details)] ?? 'Pending') : 'Pending';

					const isValidatedPatch = details?.patch_status === 'validated_patch' || details?.validated_patch === true;
					const patchBadge = isValidatedPatch ? 'Validated Patch' : 'Unvalidated Patch';

					const markdown = new vscode.MarkdownString();
					markdown.appendMarkdown(`# 🔒 Security Issue: ${title}\n\n`);
					markdown.appendMarkdown(`- **Verification:** **[${verdictBadge}]**\n`);
					markdown.appendMarkdown(`- **Patch Status:** **[${patchBadge}]**\n`);
					markdown.appendMarkdown(`- **Provider:** ${settingsManager.provider}\n`);
					markdown.appendMarkdown(`- **Sandbox Policy:** ${settingsManager.sandboxPolicy}\n\n`);

					const description = details?.description || diagnostic.message;
					markdown.appendMarkdown(`${description}\n\n`);

					const evidence = details?.evidence;
					if (details?.verified && evidence?.sink) {
						// Fenced so attacker-controlled text renders literally.
						const fence = (text: string) => '```\n' + text.replace(/```/g, '` ``') + '\n```\n\n';
						markdown.appendMarkdown(`## 🧪 Sandbox proof\n\nAttack input${evidence.payload_source === 'llm' ? ' (AI-written from the trace)' : ''}:\n\n`);
						markdown.appendMarkdown(fence(evidence.payload ?? ''));
						markdown.appendMarkdown(`The dangerous call received (${evidence.sink.kind}):\n\n`);
						markdown.appendMarkdown(fence(evidence.sink.argument));
					} else if (details?.unconfirmed_note) {
						markdown.appendMarkdown(`> ${details.unconfirmed_note}\n\n`);
					}

					markdown.appendMarkdown(`---\n\n`);
					markdown.appendMarkdown(`## 🔧 Suggested Fix (${patchBadge})\n\n`);
					markdown.appendMarkdown(`\`\`\`${document.languageId}\n${remediation}\n\`\`\`\n\n`);
					markdown.appendMarkdown(`💡 **Quick Fix:** Click the lightbulb to apply with surrounding code preservation.\n\n`);
					markdown.isTrusted = true;
					return new vscode.Hover(markdown);
				}
				return null;
			}
		}
	);

	// Register commands
	const scanFileCmd = vscode.commands.registerCommand('sageArmor.scanFile', async () => {
		const editor = vscode.window.activeTextEditor;
		if (!editor) {
			vscode.window.showWarningMessage('No active editor');
			return;
		}
		statusBar.text = `🛡️ Sage Armor: Scanning...`;
		await scannerManager.scanFile(editor.document);
		refreshSidebarAndStatus();
	});

	const rescanActiveFileCmd = vscode.commands.registerCommand('sageArmor.rescanActiveFile', async () => {
		const editor = vscode.window.activeTextEditor;
		if (!editor) {
			return;
		}

		await scannerManager.scanFile(editor.document, false);
		refreshSidebarAndStatus();
	});

	const scanWorkspaceCmd = vscode.commands.registerCommand('sageArmor.scanWorkspace', async () => {
		if (!vscode.workspace.workspaceFolders) {
			vscode.window.showWarningMessage('No workspace open');
			return;
		}
		statusBar.text = '🛡️ Sage Armor: Scanning workspace...';
		await scannerManager.scanWorkspace();
		refreshSidebarAndStatus();
	});

	const openIssueCmd = vscode.commands.registerCommand(
		'sageArmor.openIssue',
		async (uri: vscode.Uri, range: vscode.Range) => {
			const document = await vscode.workspace.openTextDocument(uri);
			const editor = await vscode.window.showTextDocument(document);
			editor.selection = new vscode.Selection(range.start, range.start);
			editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
		}
	);

	const settingsCmd = vscode.commands.registerCommand('sageArmor.openSettings', async () => {
		await vscode.commands.executeCommand('workbench.action.openSettings', 'sageArmor');
	});

	const advancedSettingsCmd = vscode.commands.registerCommand('sageArmor.openAdvancedSettings', async () => {
		advancedSettingsPanel.show(context);
	});

	const previewFixCmd = vscode.commands.registerCommand(
		'sageArmor.previewFix',
		async (title: string, remediation: string, originalSnippet?: string, startLine = 1) => {
			const diffContent = originalSnippet
				? createDiffHunk(originalSnippet, remediation, startLine)
				: `// Fix for: ${title}\n${remediation}\n`;

			const doc = await vscode.workspace.openTextDocument({
				language: originalSnippet ? 'diff' : 'javascript',
				content: diffContent,
			});
			await vscode.window.showTextDocument(doc, { preview: true });
		}
	);

	const applyUnverifiedFixCmd = vscode.commands.registerCommand(
		'sageArmor.applyUnverifiedFix',
		async (uri: vscode.Uri, replacementRange: vscode.Range, replacement: string, title: string) => {
			const choice = await vscode.window.showWarningMessage(
				`This is a generic suggested fix for ${title}. It has not been checked by the fix gates (exploit replay, behaviour tests, rescan). Apply it anyway?`,
				{ modal: true },
				'Apply Fix'
			);
			if (choice !== 'Apply Fix') return;
			const edit = new vscode.WorkspaceEdit();
			edit.replace(uri, replacementRange, replacement);
			await vscode.workspace.applyEdit(edit);
		}
	);

	const output = vscode.window.createOutputChannel('Sage Armor Fixes');

	const generateVerifiedFixCmd = vscode.commands.registerCommand(
		'sageArmor.generateVerifiedFix',
		async (uri?: vscode.Uri, finding?: Vulnerability) => {
			const document = uri
				? await vscode.workspace.openTextDocument(uri)
				: vscode.window.activeTextEditor?.document;
			if (!document || !finding) {
				vscode.window.showWarningMessage('Use this from the Sage Armor quick fix on a finding.');
				return;
			}
			const startVersion = document.version;
			const original = document.getText();
			let job: any;
			try {
				job = await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: `Sage Armor: fixing ${finding.title}`,
						cancellable: true,
					},
					(progress, token) => client.generateVerifiedFix(
						original,
						document.languageId,
						buildFixFinding(finding),
						(message) => progress.report({ message }),
						() => token.isCancellationRequested,
					)
				);
			} catch (err: any) {
				if (err?.message !== 'Cancelled') {
					vscode.window.showErrorMessage(`Verified fix failed: ${err.message}`);
				}
				return;
			}

			const fix = pickGatedFix(job);
			if (!fix || !fix.fixed_code || fix.fixed_code === original) {
				vscode.window.showWarningMessage(fix ? describeGatedFix(finding.title, fix) : `No fix could be produced for ${finding.title}.`);
				return;
			}
			// Emit the outcome: the finding now carries the patch status the gates gave it.
			finding.patch_status = toFindingPatchStatus(fix.patch_status);
			finding.validated_patch = fix.patch_status === 'verified';
			output.appendLine(`[${new Date().toISOString()}] ${document.uri.fsPath}: ${finding.title} -> patch_status=${fix.patch_status}`);
			for (const g of fix.verification_gates || []) {
				output.appendLine(`  ${g.status === 'pass' ? '✓' : g.status === 'skipped' ? '–' : '✗'} ${g.label || g.gate}: ${g.detail}`);
			}

			if (document.version !== startVersion) {
				vscode.window.showWarningMessage('The file changed while the fix was being verified; nothing was applied. Run the fix again.');
				return;
			}

			const fixedCode = fix.fixed_code;
			const applyGatedPatch = async () => {
				const edit = new vscode.WorkspaceEdit();
				const full = new vscode.Range(document.positionAt(0), document.positionAt(original.length));
				edit.replace(document.uri, full, fixedCode);
				await vscode.workspace.applyEdit(edit);
				await vscode.commands.executeCommand('sageArmor.rescanActiveFile');
			};
			const preview = async () => {
				const right = await vscode.workspace.openTextDocument({ language: document.languageId, content: fixedCode });
				await vscode.commands.executeCommand('vscode.diff', document.uri, right.uri, `${finding.title}: proposed fix`);
			};

			if (fix.patch_status === 'verified') {
				await applyGatedPatch();
				const choice = await vscode.window.showInformationMessage(describeGatedFix(finding.title, fix), 'Show gate results');
				if (choice) {
					output.show(true);
				}
				return;
			}
			const choice = await vscode.window.showWarningMessage(
				`${describeGatedFix(finding.title, fix)} Apply the unverified draft anyway?`,
				{ modal: true },
				'Preview diff',
				'Apply draft'
			);
			if (choice === 'Apply draft') {
				await applyGatedPatch();
			} else if (choice === 'Preview diff') {
				await preview();
			}
			output.show(true);
		}
	);

	const attackPathCmd = vscode.commands.registerCommand('sageArmor.attackPath', async () => {
		const editor = vscode.window.activeTextEditor;
		if (!editor) {
			vscode.window.showWarningMessage('Open a file first to generate an attack path');
			return;
		}
		try {
			const code = editor.document.getText();
			const lang = scannerManager.getLanguageForDocument(editor.document);
			const data = await client.getAttackPath(code, lang);
			const doc = await vscode.workspace.openTextDocument({
				language: 'json',
				content: JSON.stringify(data, null, 2),
			});
			await vscode.window.showTextDocument(doc, { preview: true });
		} catch (err: any) {
			vscode.window.showErrorMessage(`Attack path generation failed: ${err.message}`);
		}
	});

	const riskScoreCmd = vscode.commands.registerCommand('sageArmor.riskScore', async () => {
		const editor = vscode.window.activeTextEditor;
		if (!editor) {
			vscode.window.showWarningMessage('Open a file first to view risk scores');
			return;
		}
		try {
			const code = editor.document.getText();
			const data = await client.getRiskScore([], code);
			const doc = await vscode.workspace.openTextDocument({
				language: 'json',
				content: JSON.stringify(data, null, 2),
			});
			await vscode.window.showTextDocument(doc, { preview: true });
		} catch (err: any) {
			vscode.window.showErrorMessage(`Risk scoring failed: ${err.message}`);
		}
	});

	const copilotChatCmd = vscode.commands.registerCommand('sageArmor.copilotChat', async () => {
		const editor = vscode.window.activeTextEditor;
		const question = await vscode.window.showInputBox({
			prompt: 'Ask Sage Armor Security Copilot',
			placeHolder: 'e.g. How do I fix the SQL injection vulnerability?',
		});
		if (!question) return;

		try {
			const code = editor ? editor.document.getText() : '';
			const data = await client.askCopilot(question, [], code);
			const answer = data?.answer || 'No answer returned';
			const doc = await vscode.workspace.openTextDocument({
				language: 'markdown',
				content: `# Sage Armor Copilot\n\n**Question:** ${question}\n\n**Answer:**\n${answer}\n`,
			});
			await vscode.window.showTextDocument(doc, { preview: true });
		} catch (err: any) {
			vscode.window.showErrorMessage(`Copilot error: ${err.message}`);
		}
	});

	const repoScanCmd = vscode.commands.registerCommand('sageArmor.repoScan', async (presetUrl?: string) => {
		const repoUrl = await vscode.window.showInputBox({
			prompt: 'Repository URL to scan',
			placeHolder: 'https://github.com/org/repo',
			value: typeof presetUrl === 'string' ? presetUrl : undefined,
		});
		if (!repoUrl) return;

		try {
			const startRes = await client.startRepoScan(repoUrl);
			const jobId = startRes.job_id;
			await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: `Scanning ${repoUrl}`,
					cancellable: true,
				},
				async (progress, token) => {
					token.onCancellationRequested(async () => {
						await client.cancelRepoScan(jobId);
					});

					while (!token.isCancellationRequested) {
						await new Promise((r) => setTimeout(r, 1000));
						const statusRes = await client.getRepoScanStatus(jobId);
						progress.report({
							message: `${statusRes.stage || statusRes.status} (${statusRes.progress || 0}%)`,
						});
						if (statusRes.status === 'completed' || statusRes.status === 'failed' || statusRes.status === 'cancelled') {
							if (statusRes.status === 'completed') {
								// Kept so "Start Repository Autofix" can send real findings with their file paths.
								await context.workspaceState.update('sageArmor.lastRepoScan', {
									repoUrl,
									findings: repoFindingsForAutofix(statusRes),
								});
								vscode.window.showInformationMessage(`Repo scan complete: ${statusRes.summary || 'Done'}`);
							} else {
								vscode.window.showWarningMessage(`Repo scan ended with status: ${statusRes.status}`);
							}
							break;
						}
					}
				}
			);
		} catch (err: any) {
			vscode.window.showErrorMessage(`Repo scan failed: ${err.message}`);
		}
	});

	const repoAutofixCmd = vscode.commands.registerCommand('sageArmor.repoAutofix', async () => {
		const last = context.workspaceState.get<{ repoUrl: string; findings: Record<string, unknown>[] }>('sageArmor.lastRepoScan');
		const repoUrl = await vscode.window.showInputBox({
			prompt: 'Repository URL for autofix (uses the findings of your last repository scan)',
			placeHolder: 'https://github.com/org/repo',
			value: last?.repoUrl,
		});
		if (!repoUrl) return;

		const findings = last && last.repoUrl === repoUrl ? last.findings : [];
		if (!findings.length) {
			const choice = await vscode.window.showWarningMessage(
				'Autofix needs findings with file paths. Run a repository scan of this URL first.',
				'Scan repository'
			);
			if (choice) {
				await vscode.commands.executeCommand('sageArmor.repoScan', repoUrl);
			}
			return;
		}

		const modePick = await vscode.window.showQuickPick(
			[
				{ label: 'Suggest fixes', description: 'Generate and verify patches; change nothing', mode: 'suggest' },
				{ label: 'Open a pull request', description: 'Commit only patches that pass every gate', mode: 'pr' },
			],
			{ placeHolder: `${findings.length} finding(s) from the last scan of ${repoUrl}` }
		);
		if (!modePick) return;

		try {
			const startRes = await client.startAutofix(repoUrl, findings, modePick.mode);
			const jobId = startRes.job_id;
			const job = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: `Sage Armor autofix: ${repoUrl}`, cancellable: false },
				async (progress) => {
					const deadline = Date.now() + 30 * 60 * 1000;
					while (Date.now() < deadline) {
						await new Promise((r) => setTimeout(r, 3000));
						const status = await client.getAutofixStatus(jobId);
						const logs: string[] = Array.isArray(status?.logs) ? status.logs : [];
						progress.report({ message: logs[logs.length - 1] || `${status?.stage || status?.status} (${status?.progress || 0}%)` });
						if (status?.status === 'completed' || status?.status === 'failed' || status?.status === 'interrupted') {
							return status;
						}
					}
					throw new Error('Timed out waiting for the autofix job');
				}
			);
			if (job?.status !== 'completed') {
				vscode.window.showErrorMessage(`Autofix ${job?.status}: ${job?.error || ''}`);
				return;
			}
			output.appendLine(`[${new Date().toISOString()}] Autofix ${repoUrl}: ${job.summary || ''}`);
			for (const r of job.results || []) {
				output.appendLine(`  ${r.patch_status === 'verified' ? '🛡️' : '⚠️'} ${r.file_path} ${r.issue}: patch_status=${r.patch_status}${r.applied ? ' (applied)' : ''}`);
				for (const g of r.verification_gates || []) {
					output.appendLine(`      ${g.status === 'pass' ? '✓' : g.status === 'skipped' ? '–' : '✗'} ${g.label || g.gate}: ${g.detail}`);
				}
			}
			const buttons = job.pr_url ? ['Open pull request', 'Show details'] : ['Show details'];
			const choice = await vscode.window.showInformationMessage(`Autofix complete: ${job.summary || 'done'}`, ...buttons);
			if (choice === 'Open pull request' && job.pr_url) {
				vscode.env.openExternal(vscode.Uri.parse(job.pr_url));
			} else if (choice) {
				output.show(true);
			}
		} catch (err: any) {
			vscode.window.showErrorMessage(`Autofix failed: ${err.message}`);
		}
	});

	const testCmd = vscode.commands.registerCommand('sageArmor.testConnection', async () => {
		try {
			const result = await client.testConnection();
			if (result) {
				vscode.window.showInformationMessage('✅ Backend connection successful');
			} else {
				vscode.window.showErrorMessage(
					`❌ Backend connection failed. Verify sageArmor.backendUrl and backend health.`
				);
			}
		} catch (error) {
			vscode.window.showErrorMessage(`❌ Connection error: ${error}`);
		}
	});

	// Watch file saves
	const saveWatcher = vscode.workspace.onDidSaveTextDocument(async (document) => {
		if (settingsManager.scanOnSave && scannerManager.isSupportedDocument(document)) {
			statusBar.text = '🛡️ Sage Armor: Scanning...';
			await scannerManager.scanFile(document);
			refreshSidebarAndStatus();
		}
	});

	const changeWatcher = vscode.workspace.onDidChangeTextDocument(async (event) => {
		const isUndoOrRedo =
			event.reason === vscode.TextDocumentChangeReason.Undo ||
			event.reason === vscode.TextDocumentChangeReason.Redo;

		if (!settingsManager.scanOnKeystroke && !isUndoOrRedo) {
			return;
		}

		if (!scannerManager.isSupportedDocument(event.document)) {
			return;
		}

		statusBar.text = '🛡️ Sage Armor: Scanning...';
		await scannerManager.scanFile(event.document, false, 'rules-only');
		refreshSidebarAndStatus();
	});

	const diagnosticsWatcher = vscode.languages.onDidChangeDiagnostics(() => {
		refreshSidebarAndStatus();
	});

	// Register subscriptions
	context.subscriptions.push(scanFileCmd);
	context.subscriptions.push(rescanActiveFileCmd);
	context.subscriptions.push(scanWorkspaceCmd);
	context.subscriptions.push(settingsCmd);
	context.subscriptions.push(advancedSettingsCmd);
	context.subscriptions.push(testCmd);
	context.subscriptions.push(openIssueCmd);
	context.subscriptions.push(previewFixCmd);
	context.subscriptions.push(applyUnverifiedFixCmd);
	context.subscriptions.push(generateVerifiedFixCmd);
	context.subscriptions.push(output);
	context.subscriptions.push(attackPathCmd);
	context.subscriptions.push(riskScoreCmd);
	context.subscriptions.push(copilotChatCmd);
	context.subscriptions.push(repoScanCmd);
	context.subscriptions.push(repoAutofixCmd);
	context.subscriptions.push(saveWatcher);
	context.subscriptions.push(changeWatcher);
	context.subscriptions.push(diagnosticsWatcher);
	context.subscriptions.push(statusBar);
	context.subscriptions.push(sidebarView);
	context.subscriptions.push(codeActionProvider);
	context.subscriptions.push(hoverProvider);

	refreshSidebarAndStatus();

	// Show welcome message
	vscode.window.showInformationMessage('🛡️ Sage Armor Security Scanner loaded');
}

class SageArmorCodeActionProvider implements vscode.CodeActionProvider {
	private diagManager: DiagnosticsManager;

	constructor(diagManager: DiagnosticsManager) {
		this.diagManager = diagManager;
	}

	provideCodeActions(
		document: vscode.TextDocument,
		range: vscode.Range | vscode.Selection,
		context: vscode.CodeActionContext,
		_token: vscode.CancellationToken
	): vscode.CodeAction[] {
		const actions: vscode.CodeAction[] = [];

		for (const diagnostic of context.diagnostics) {
			const isDiagnosticSageArmor =
				typeof diagnostic.code === 'string' && diagnostic.code.startsWith('sage-armor-fix:');

			if (!isDiagnosticSageArmor) {
				continue;
			}

			const key = (diagnostic.code as string).replace('sage-armor-fix:', '');
			const rawRemediation = this.diagManager.getRemediation(key);
			const fixRange = this.diagManager.getFixRange(key);
			const title = diagnostic.message.split(':')[0];

			if (!rawRemediation || rawRemediation.trim() === '') {
				console.log('[CodeAction] Skipping - no remediation for:', { key, title });
				continue;
			}

			// Adapt remediation for language
			const adaptedRemediation = adaptRemediationForLanguage(title, rawRemediation, document.languageId);

			if (!adaptedRemediation || adaptedRemediation.trim() === '') {
				console.log('[CodeAction] Skipping - no adapted remediation');
				continue;
			}

			// Get line text and normalize indentation
			const lineText = document.lineAt(diagnostic.range.start.line).text;
			const indentation = lineText.match(/^\s*/)?.[0] || '';
			const normalizedRemediation = normalizeRemediation(adaptedRemediation, indentation);
			const startLine = fixRange?.start.line ?? diagnostic.range.start.line;
			const endLine = fixRange?.end.line ?? diagnostic.range.end.line;
			const replacementRange = new vscode.Range(
				startLine,
				0,
				endLine,
				document.lineAt(endLine).text.length
			);

			const details = this.diagManager.getDetails(key);

			// The backend's gated fix loop: exploit replay, behaviour tests, rescan (Python only).
			if (document.languageId === 'python' && details) {
				const gated = new vscode.CodeAction(`🛡️ Generate verified fix: ${title}`, vscode.CodeActionKind.QuickFix);
				gated.command = {
					command: 'sageArmor.generateVerifiedFix',
					title: 'Generate verified fix',
					arguments: [document.uri, details],
				};
				gated.diagnostics = [diagnostic];
				gated.isPreferred = true;
				actions.push(gated);
			}

			// "Verified" describes the patch, not the finding: only a patch that passed the fix
			// gates may be applied without confirmation. Template suggestions never have.
			const requiresConfirmation = details?.patch_status !== 'validated_patch';
			const action = new vscode.CodeAction(
				requiresConfirmation ? `🔧 Review suggested fix (not verified): ${title}` : `🔧 Apply verified fix: ${title}`,
				vscode.CodeActionKind.QuickFix
			);
		if (requiresConfirmation) {
			action.command = {
				command: 'sageArmor.applyUnverifiedFix',
				title: 'Confirm and apply unverified fix',
				arguments: [document.uri, replacementRange, normalizedRemediation, title],
			};
		} else {
			action.edit = new vscode.WorkspaceEdit();
			action.edit.replace(document.uri, replacementRange, normalizedRemediation);
			action.command = {
				command: 'sageArmor.rescanActiveFile',
				title: 'Rescan Sage Armor diagnostics',
			};
		}

			action.diagnostics = [diagnostic];
			action.isPreferred = !requiresConfirmation;
			actions.push(action);

			// Add preview action
			const preview = new vscode.CodeAction(
				`📋 Preview fix: ${title}`,
				vscode.CodeActionKind.QuickFix
			);
			preview.command = {
				command: 'sageArmor.previewFix',
				title: 'Preview Fix',
				arguments: [title, normalizedRemediation, document.getText(replacementRange), startLine + 1],
			};
			actions.push(preview);
		}

		return actions;
	}
}

export function deactivate() {
	console.log('Sage Armor Scanner deactivated');
	diagnosticsManager?.dispose();
}
