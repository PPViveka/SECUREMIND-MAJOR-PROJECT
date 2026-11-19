import type { ReactNode } from 'react';

/**
 * Minimal, safe Markdown renderer for copilot replies.
 * Supports fenced code blocks, headings, bullet and numbered lists,
 * **bold**, *italic* and `inline code`. Builds React nodes (no innerHTML).
 */

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let i = 0;
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) nodes.push(text.slice(last, match.index));
    const token = match[0];
    const key = `${keyPrefix}-${i++}`;
    if (token.startsWith('`')) {
      nodes.push(<code key={key} className="px-1 py-0.5 rounded bg-black/40 text-cyan-300 font-mono text-[0.85em]">{token.slice(1, -1)}</code>);
    } else if (token.startsWith('**')) {
      nodes.push(<strong key={key} className="font-semibold text-white">{token.slice(2, -2)}</strong>);
    } else {
      nodes.push(<em key={key}>{token.slice(1, -1)}</em>);
    }
    last = match.index + token.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function renderTextBlock(block: string, blockKey: string): ReactNode[] {
  const out: ReactNode[] = [];
  const lines = block.split('\n');
  let list: { ordered: boolean; items: string[] } | null = null;
  let paragraph: string[] = [];

  const flushParagraph = () => {
    if (paragraph.length) {
      const k = `${blockKey}-p${out.length}`;
      out.push(<p key={k} className="leading-relaxed">{renderInline(paragraph.join(' '), k)}</p>);
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list) {
      const k = `${blockKey}-l${out.length}`;
      const items = list.items.map((item, idx) => <li key={`${k}-${idx}`}>{renderInline(item, `${k}-${idx}`)}</li>);
      out.push(list.ordered
        ? <ol key={k} className="list-decimal pl-5 space-y-1">{items}</ol>
        : <ul key={k} className="list-disc pl-5 space-y-1">{items}</ul>);
      list = null;
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    const heading = /^#{1,6}\s+(.*)$/.exec(line);
    const bullet = /^\s*[-*•]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (!line.trim()) {
      flushParagraph();
      flushList();
    } else if (heading) {
      flushParagraph();
      flushList();
      const k = `${blockKey}-h${out.length}`;
      out.push(<p key={k} className="font-semibold text-white mt-1">{renderInline(heading[1], k)}</p>);
    } else if (bullet || numbered) {
      flushParagraph();
      const ordered = Boolean(numbered && !bullet);
      if (list && list.ordered !== ordered) flushList();
      if (!list) list = { ordered, items: [] };
      list.items.push((bullet || numbered)![1]);
    } else {
      flushList();
      paragraph.push(line.trim());
    }
  }
  flushParagraph();
  flushList();
  return out;
}

export function ChatMarkdown({ text }: { text: string }) {
  const parts = text.split(/```/);
  return (
    <div className="space-y-2 break-words">
      {parts.map((part, idx) => {
        if (idx % 2 === 1) {
          const firstNewline = part.indexOf('\n');
          const lang = firstNewline > -1 ? part.slice(0, firstNewline).trim() : '';
          const code = firstNewline > -1 ? part.slice(firstNewline + 1) : part;
          return (
            <div key={`c${idx}`} className="rounded-lg border border-white/10 bg-black/60 overflow-hidden">
              {lang && <div className="px-3 py-1 text-[10px] uppercase tracking-wider text-white/40 border-b border-white/10">{lang}</div>}
              <pre className="p-3 text-xs font-mono text-cyan-200 overflow-x-auto"><code>{code.replace(/\n$/, '')}</code></pre>
            </div>
          );
        }
        return <div key={`t${idx}`} className="space-y-2">{renderTextBlock(part, `t${idx}`)}</div>;
      })}
    </div>
  );
}
