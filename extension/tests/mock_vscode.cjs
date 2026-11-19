const Module = require('node:module');

const mockVscode = {
  languages: {
    createDiagnosticCollection: () => ({
      set: () => {},
      delete: () => {},
      clear: () => {},
      dispose: () => {},
    }),
    getDiagnostics: () => [],
    registerCodeActionsProvider: () => ({ dispose: () => {} }),
    registerHoverProvider: () => ({ dispose: () => {} }),
    onDidChangeDiagnostics: () => ({ dispose: () => {} }),
  },
  window: {
    createStatusBarItem: () => ({
      text: '',
      show: () => {},
      dispose: () => {},
    }),
    createTreeView: () => ({ dispose: () => {} }),
    showInformationMessage: async () => {},
    showWarningMessage: async () => {},
    showErrorMessage: async () => {},
    showInputBox: async () => '',
    showTextDocument: async () => ({
      selection: null,
      revealRange: () => {},
    }),
    withProgress: async (opts, task) => {
      return task({ report: () => {} }, { isCancellationRequested: false, onCancellationRequested: () => {} });
    },
    activeTextEditor: undefined,
  },
  workspace: {
    getConfiguration: () => ({
      get: (k, def) => def,
      update: async () => {},
    }),
    openTextDocument: async () => ({
      getText: () => '',
      lineAt: () => ({ text: '' }),
      fileName: 'test.py',
      languageId: 'python',
      uri: { toString: () => 'file:///test.py', path: '/test.py', fsPath: '/test.py' },
    }),
    applyEdit: async () => true,
    findFiles: async () => [],
    onDidSaveTextDocument: () => ({ dispose: () => {} }),
    onDidChangeTextDocument: () => ({ dispose: () => {} }),
    workspaceFolders: [{ uri: { fsPath: '/mock/workspace' } }],
  },
  commands: {
    registerCommand: () => ({ dispose: () => {} }),
    executeCommand: async () => {},
  },
  Range: class Range {
    constructor(start, end) {
      this.start = start;
      this.end = end;
    }
  },
  Position: class Position {
    constructor(line, character) {
      this.line = line;
      this.character = character;
    }
  },
  Diagnostic: class Diagnostic {
    constructor(range, message, severity) {
      this.range = range;
      this.message = message;
      this.severity = severity;
    }
  },
  DiagnosticSeverity: {
    Error: 0,
    Warning: 1,
    Information: 2,
    Hint: 3,
  },
  ThemeIcon: class ThemeIcon {
    constructor(id) {
      this.id = id;
    }
  },
  TreeItem: class TreeItem {
    constructor(label, collapsibleState) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  },
  TreeItemCollapsibleState: {
    None: 0,
    Collapsed: 1,
    Expanded: 2,
  },
  EventEmitter: class EventEmitter {
    constructor() {
      this.event = () => ({ dispose: () => {} });
    }
    fire() {}
  },
  CodeAction: class CodeAction {
    constructor(title, kind) {
      this.title = title;
      this.kind = kind;
    }
  },
  CodeActionKind: {
    QuickFix: 'quickfix',
  },
  WorkspaceEdit: class WorkspaceEdit {
    replace() {}
  },
  MarkdownString: class MarkdownString {
    constructor() {
      this.value = '';
    }
    appendMarkdown(v) {
      this.value += v;
    }
  },
  Hover: class Hover {
    constructor(contents) {
      this.contents = contents;
    }
  },
  Selection: class Selection {
    constructor(anchor, active) {
      this.anchor = anchor;
      this.active = active;
    }
  },
  StatusBarAlignment: {
    Left: 1,
    Right: 2,
  },
  TextEditorRevealType: {
    InCenter: 1,
  },
  ConfigurationTarget: {
    Global: 1,
    Workspace: 2,
  },
  ProgressLocation: {
    Notification: 15,
  },
  TextDocumentChangeReason: {
    Undo: 1,
    Redo: 2,
  },
};

const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain) {
  if (request === 'vscode') {
    return 'vscode';
  }
  return originalResolve.call(this, request, parent, isMain);
};

require.cache['vscode'] = {
  id: 'vscode',
  filename: 'vscode',
  loaded: true,
  exports: mockVscode,
};

module.exports = mockVscode;
