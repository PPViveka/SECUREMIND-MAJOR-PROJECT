import { useState } from 'react';
import { ChevronDown, ChevronRight, FlaskConical } from 'lucide-react';

type Attempt = {
  n: number;
  source: 'fixed' | 'llm';
  payload: string;
  kwargs?: Record<string, unknown>;
  status: 'proved' | 'failed';
  stopped_at?: { line: number; code: string } | null;
  error?: string | null;
  reasoning?: string;
};

export type Evidence = {
  payload?: string;
  kwargs?: Record<string, unknown>;
  payload_source?: 'fixed' | 'llm' | null;
  sink?: { kind: string; argument: string } | null;
  sink_line_reached?: boolean;
  executed_lines?: number[];
  llm_used?: boolean;
  attempts?: Attempt[];
  reason?: string;
};

const SINK_LABEL: Record<string, string> = {
  sql: 'SQL query sent to the database',
  command: 'Shell command',
  file: 'File path opened',
  eval: 'Code passed to eval()',
  exec: 'Code passed to exec()',
  http: 'URL requested by the server',
  redirect: 'Redirect target',
  deserialize: 'Data given to the deserializer',
  template: 'Template source rendered',
  response: 'HTML response body',
  return: 'HTML returned to the browser',
};

/** What the sandbox did to prove (or fail to prove) a finding. */
export function SandboxEvidence({ evidence, verdict }: { evidence?: Evidence; verdict: string }) {
  const [open, setOpen] = useState(false);
  const attempts = evidence?.attempts || [];
  if (!evidence || (!evidence.sink && attempts.length === 0 && !evidence.reason)) return null;

  const proved = verdict === 'verified' && !!evidence.sink;
  const tone = proved
    ? 'bg-green-950/20 border-green-800/40'
    : 'bg-white/[0.03] border-white/10';

  return (
    <div className={`mb-6 p-4 rounded-xl border ${tone}`}>
      <div className="flex items-center gap-2 mb-3">
        <FlaskConical className={`w-4 h-4 ${proved ? 'text-green-400' : 'text-white/50'}`} />
        <span className={`text-[10px] font-bold uppercase tracking-widest ${proved ? 'text-green-400' : 'text-white/50'}`}>
          {proved ? 'Sandbox proof' : 'Sandbox attack'}
        </span>
        {attempts.length > 0 && (
          <span className="text-[10px] text-white/40">
            {attempts.length} attempt{attempts.length === 1 ? '' : 's'}
            {evidence.llm_used ? ' · AI-written inputs used' : ''}
          </span>
        )}
      </div>

      {proved && evidence.sink ? (
        <div className="space-y-2 text-xs">
          <div>
            <div className="text-white/40 mb-1">
              Attack input{evidence.payload_source === 'llm' ? ' (written by the AI from the trace)' : ''}
            </div>
            <code className="block whitespace-pre-wrap break-all bg-black/40 rounded-lg px-3 py-2 text-amber-200">
              {evidence.payload}
              {evidence.kwargs && Object.keys(evidence.kwargs).length > 0 ? `\nkwargs: ${JSON.stringify(evidence.kwargs)}` : ''}
            </code>
          </div>
          <div>
            <div className="text-white/40 mb-1">{SINK_LABEL[evidence.sink.kind] || 'Dangerous call received'}</div>
            <code className="block whitespace-pre-wrap break-all bg-black/40 rounded-lg px-3 py-2 text-red-200">{evidence.sink.argument}</code>
          </div>
          <p className="text-white/50">
            The input reached this call with its attack syntax intact.
            {evidence.executed_lines?.length ? ` Lines run in the function: ${evidence.executed_lines.join(', ')}.` : ''}
          </p>
        </div>
      ) : (
        <p className="text-xs text-white/60">
          {evidence.reason || 'No attack input carried its marker into a dangerous call.'}
        </p>
      )}

      {attempts.length > 0 && (
        <div className="mt-3">
          <button
            onClick={() => setOpen(o => !o)}
            className="flex items-center gap-1 text-[11px] text-white/50 hover:text-white/80 transition-colors"
          >
            {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            What the sandbox tried
          </button>
          {open && (
            <ol className="mt-2 space-y-2">
              {attempts.map(a => (
                <li key={a.n} className="text-[11px] leading-relaxed">
                  <span className={a.status === 'proved' ? 'text-green-300' : 'text-white/40'}>
                    {a.n}. {a.source === 'llm' ? 'AI' : 'Fixed'} · {a.status === 'proved' ? 'reached the sink' : 'failed'}
                  </span>
                  <code className="block break-all text-white/70">{a.payload}{a.kwargs ? ` ${JSON.stringify(a.kwargs)}` : ''}</code>
                  {a.status !== 'proved' && (
                    <span className="text-white/40">
                      {a.stopped_at ? `Stopped at line ${a.stopped_at.line}: ${a.stopped_at.code}` : 'The function body did not run.'}
                      {a.error ? ` (${a.error})` : ''}
                    </span>
                  )}
                  {a.reasoning && <span className="block text-white/40 italic">{a.reasoning}</span>}
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}
