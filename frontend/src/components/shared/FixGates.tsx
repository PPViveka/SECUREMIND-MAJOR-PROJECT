import { useState } from 'react';
import { CheckCircle2, ChevronDown, ChevronRight, CircleSlash, XCircle } from 'lucide-react';

export type BehaviourCase = {
  input: string;
  kwargs?: Record<string, unknown>;
  verdict: 'same' | 'changed' | 'not_compared';
  reason?: string;
};

export type FixGate = {
  gate: string;
  label?: string;
  status?: 'pass' | 'fail' | 'error' | 'skipped' | string;
  passed?: boolean;
  detail: string;
  issue?: string;
  behaviour?: BehaviourCase[];
  evidence?: { attempts?: { source?: string }[] };
};

const FALLBACK_LABEL: Record<string, string> = {
  formatter: 'Project formatter',
  gate_a_parse_compile: 'Parses and compiles',
  gate_e_diff_constraints: 'Small, in-bounds diff',
  exploit_blocked: 'Exploit blocked',
  tests_pass: 'Behaviour and tests preserved',
  no_new_sast_findings: 'Security rescan clean',
};

function statusOf(g: FixGate): string {
  return g.status || (g.passed ? 'pass' : 'fail');
}

/** Strip the "Gate X PASS:" prefix the backend uses in its logs. */
function cleanDetail(detail: string): string {
  return detail.replace(/^Gate [A-E] (PASS|FAIL|ERROR|SKIPPED):\s*/, '');
}

/** Checklist of the verification gates a generated patch went through. */
export function FixGates({ gates }: { gates?: FixGate[] }) {
  const [openIdx, setOpenIdx] = useState<number | null>(null);
  if (!gates?.length) return null;
  return (
    <ul className="space-y-1.5 mb-3">
      {gates.map((g, i) => {
        const st = statusOf(g);
        const Icon = st === 'pass' ? CheckCircle2 : st === 'skipped' ? CircleSlash : XCircle;
        const tone = st === 'pass' ? 'text-green-400' : st === 'skipped' ? 'text-white/40' : 'text-red-400';
        const attempts = g.evidence?.attempts?.length || 0;
        const hasMore = !!g.behaviour?.length;
        return (
          <li key={i} className="text-[11px] leading-relaxed">
            <div className="flex items-start gap-2">
              <Icon className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${tone}`} />
              <div className="min-w-0">
                <span className={`font-semibold ${tone}`}>
                  {g.issue ? `${g.issue} · ` : ''}{g.label || FALLBACK_LABEL[g.gate] || g.gate}
                </span>
                {st === 'skipped' && <span className="text-white/40"> (not run)</span>}
                {attempts > 0 && <span className="text-white/40"> · {attempts} attack{attempts === 1 ? '' : 's'} run</span>}
                <span className="block text-white/55 break-words">{cleanDetail(g.detail)}</span>
                {hasMore && (
                  <button
                    onClick={() => setOpenIdx(openIdx === i ? null : i)}
                    className="flex items-center gap-1 text-white/40 hover:text-white/70 mt-0.5"
                  >
                    {openIdx === i ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                    Normal inputs compared
                  </button>
                )}
                {openIdx === i && g.behaviour && (
                  <ul className="mt-1 space-y-0.5">
                    {g.behaviour.map((c, ci) => (
                      <li key={ci} className="font-mono text-white/60">
                        <span className={c.verdict === 'same' ? 'text-green-300' : c.verdict === 'changed' ? 'text-red-300' : 'text-white/40'}>
                          {c.verdict === 'same' ? '=' : c.verdict === 'changed' ? '≠' : '?'}
                        </span>{' '}
                        {JSON.stringify(c.input)}
                        {c.kwargs && Object.keys(c.kwargs).length > 0 ? ` ${JSON.stringify(c.kwargs)}` : ''}
                        <span className="text-white/40"> — {c.reason}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function PatchBadge({ status }: { status?: string }) {
  if (status === 'verified') {
    return <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-500/20 border border-green-500/30 text-green-300 font-mono tracking-wide">🛡️ Verified fix</span>;
  }
  if (status === 'failed') {
    return <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/30 text-red-300 font-mono tracking-wide">No usable patch</span>;
  }
  return <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-300 font-mono tracking-wide">⚠️ Unverified draft</span>;
}
