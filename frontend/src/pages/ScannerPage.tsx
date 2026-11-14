import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Shield, Code2, Sparkles,
  XCircle, AlertTriangle, CheckCircle,
  MessageSquare, Send, Bug, Route, BarChart3,
} from 'lucide-react';
import { PageTransition } from '../components/shared/PageTransition';

// Inline GitHub icon
const GithubIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
  </svg>
);

/* ── Types ── */
type Vulnerability = {
  severity: string;
  issue: string;
  attack_vector?: string;
  explanation?: string;
  poc_exploit_scenario?: string;
  remediation?: { patch?: string; explanation?: string };
  suggested_fix?: string;
  asset_value?: string;
  exploitability_level?: string;
  score?: number;
  file_path?: string;
  verified?: boolean;
  verification_status?: 'verified' | 'unconfirmed';
  dynamic_trace?: {
    sink_reached?: boolean;
    sink_line?: number;
    executed_lines?: (string | number)[];
    vector_used?: string;
    harness_output?: string;
  };
  function_name?: string;
};
type AttackNode = { id: string; label: string; kind: string; criticality: string };
type AttackEdge = { id: string; source: string; target: string; label?: string };
type RiskItem = {
  id: string; issue: string; severity: string; priority_score: number;
  occurrence_count?: number; asset_value: string;
  exploitability: { level: string; score: number; exploitable: boolean };
};
type SimulationData = {
  chain_summary?: string; accessible_data?: string[];
  likely_impact?: string[]; compromise_probability?: string;
};
type ChatMessage = { role: 'user' | 'assistant'; text: string };

const getSeverityLevel = (sev?: string) => {
  const s = (sev || '').toLowerCase();
  if (s.includes('high') || s.includes('critical')) return 'High';
  if (s.includes('medium')) return 'Medium';
  return 'Low';
};

/* ── Severity badge styles ── */
const sevStyle = (level: string) => {
  if (level === 'High') return { 
    card: 'bg-red-500/10 border-red-500/30', 
    badge: 'bg-red-500/20 text-red-300', 
    iconColor: 'text-red-400', 
    IconComp: XCircle,
    accent: 'red'
  };
  if (level === 'Medium') return { 
    card: 'bg-orange-500/10 border-orange-500/30', 
    badge: 'bg-orange-500/20 text-orange-300', 
    iconColor: 'text-orange-400', 
    IconComp: AlertTriangle,
    accent: 'orange'
  };
  return { 
    card: 'bg-blue-500/10 border-blue-500/30', 
    badge: 'bg-blue-500/20 text-blue-300', 
    iconColor: 'text-blue-400', 
    IconComp: CheckCircle,
    accent: 'blue'
  };
};

const glassCard = 'backdrop-blur-xl bg-white/[0.04] border border-white/10 rounded-2xl';

export default function ScannerPage() {
  const [codeSnippet, setCodeSnippet] = useState(`import os\nimport sqlite3\n\ndef get_user(user_id):\n    # Vulnerable to SQL injection\n    conn = sqlite3.connect('users.db')\n    cursor = conn.cursor()\n    query = "SELECT * FROM users WHERE id = " + user_id\n    cursor.execute(query)\n    return cursor.fetchall()\n`);
  const [language, setLanguage] = useState('python');
  const [repoUrl, setRepoUrl] = useState('');
  const [repoBranch] = useState('main');
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'results' | 'attack' | 'simulation' | 'copilot'>('results');
  const [scanResults, setScanResults] = useState<{ vulnerabilities?: Vulnerability[] } | null>(null);
  const [attackGraph, setAttackGraph] = useState<{ nodes: AttackNode[]; edges: AttackEdge[]; attack_paths?: any[]; ast_derived?: boolean } | null>(null);
  const [riskRanking, setRiskRanking] = useState<RiskItem[]>([]);
  const [simulationData, setSimulationData] = useState<SimulationData | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([{ role: 'assistant', text: 'Ask me anything about exploitability, attack chains, or what to fix first.' }]);
  const [chatInput, setChatInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [isRepoScanning, setIsRepoScanning] = useState(false);
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [isAutoFixing, setIsAutoFixing] = useState(false);
  const [autofixJob, setAutofixJob] = useState<{
    job_id: string; status: string; stage: string; progress: number;
    results: any[]; logs: string[]; pr_url?: string; summary?: string;
  } | null>(null);
  const [scanJob, setScanJob] = useState<{
    job_id: string; status: string; stage: string; progress: number;
    vulnerabilities_partial?: any[]; vulnerabilities_full?: any[];
    repo_stats?: any; logs: string[];
  } | null>(null);
  const [autoFixResults, setAutoFixResults] = useState<{ summary: string; pr_url?: string; fixes: any[] } | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:6060';

  const postJson = async (path: string, payload: Record<string, unknown>) => {
    const res = await fetch(`${apiUrl}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    return res.json();
  };

  const pollJobStatus = async (jobId: string) => {
    let polling = true;
    while (polling) {
      try {
        const res = await fetch(`${apiUrl}/repo-autofix/status?job_id=${jobId}`);
        const job = await res.json();
        
        if (job.error || job.status === 'failed') {
          setApiError(job.error || job.logs?.slice(-1)[0] || 'AutoFix failed');
          setIsAutoFixing(false);
          polling = false;
        } else {
          setAutofixJob(job);
          
          if (job.status === 'completed') {
            setIsAutoFixing(false);
            polling = false;
            setAutoFixResults({
              summary: job.summary,
              pr_url: job.pr_url,
              fixes: job.results
            });
            
            if (job.modified_files && typeof job.modified_files === 'string') {
              setCodeSnippet(job.modified_files);
            }
          }
        }
      } catch (e) {
        setApiError('Failed to poll job status.');
        setIsAutoFixing(false);
        polling = false;
      }
      if (polling) await new Promise(r => setTimeout(r, 1500));
    }
  };

  const pollScanJobStatus = async (jobId: string) => {
    let polling = true;
    while (polling) {
      try {
        const res = await fetch(`${apiUrl}/repo-scan/status?job_id=${jobId}`);
        const job = await res.json();
        
        if (job.error || job.status === 'failed') {
          if (job.error === 'Job not found') {
            // Ignore for the first few seconds until POST kicks off creating the job
          } else {
            setApiError(job.error || job.logs?.slice(-1)[0] || 'Repo scan failed');
            setIsRepoScanning(false);
            polling = false;
          }
        } else {
          setScanJob(job);
          if (job.vulnerabilities_partial || job.vulnerabilities_full) {
             setScanResults({ vulnerabilities: job.vulnerabilities_full?.length ? job.vulnerabilities_full : job.vulnerabilities_partial });
          }
          if (job.attack_graph || job.risk_ranking) {
             setAttackGraph({ nodes: job.attack_graph?.nodes || [], edges: job.attack_graph?.edges || [], attack_paths: job.attack_graph?.attack_paths || [] });
             setRiskRanking(job.risk_ranking || []);
             setSimulationData(job.breach_simulation || null);
          }
          
          if (job.status === 'completed') {
            setIsRepoScanning(false);
            polling = false;
          }
        }
      } catch (e) {
        setApiError('Failed to poll scan job status.');
        setIsRepoScanning(false);
        polling = false;
      }
      if (polling) await new Promise(r => setTimeout(r, 1500));
    }
  };


  const handleAutoFix = async (mode: 'suggest' | 'fix' | 'pr') => {
    if (!scanResults?.vulnerabilities?.length) return;
    setIsAutoFixing(true);
    setApiError(null);
    setAutofixJob(null);
    setAutoFixResults(null);
    try {
      const payload: any = {
        vulnerabilities: scanResults.vulnerabilities,
        mode,
        github_token: localStorage.getItem('github_token') || undefined
      };

      if (repoUrl.trim()) {
        payload.repo_url = repoUrl.trim();
      } else {
        payload.code = codeSnippet;
        payload.language = language;
      }

      const data = await postJson('/repo-autofix/start', payload);
      if (data.error) {
        setApiError(data.error);
        setIsAutoFixing(false);
      } else {
        pollJobStatus(data.job_id);
      }
    } catch {
      setApiError('AutoFix start request failed. Verify backend /repo-autofix/start route is running.');
      setIsAutoFixing(false);
    }
  };

  const handleCopyFix = (v: Vulnerability, idx: number) => {
    const text = v.remediation?.patch ?? v.suggested_fix ?? '';
    navigator.clipboard.writeText(text).then(() => { setCopiedIdx(idx); setTimeout(() => setCopiedIdx(null), 2000); });
  };

  const hydrateAdvancedModules = async (vulnerabilities: Vulnerability[]) => {
    const payload = { code: codeSnippet, language, vulnerabilities };
    const [attack, risk, simulation] = await Promise.all([
      postJson('/attack-path', payload), postJson('/risk-score', payload), postJson('/simulate', payload),
    ]);
    if (!attack.error) setAttackGraph({
      nodes: attack.attack_graph?.nodes || [],
      edges: attack.attack_graph?.edges || [],
      attack_paths: attack.attack_paths || [],
      ast_derived: attack.ast_derived ?? attack.attack_graph?.ast_derived ?? false,
    });
    if (!risk.error) setRiskRanking(risk.risk_ranking || []);
    if (!simulation.error) setSimulationData(simulation.breach_simulation || null);
  };

  const handleScan = async () => {
    setIsScanning(true); setScanResults(null); setAttackGraph(null); setRiskRanking([]); setSimulationData(null); setApiError(null); setAutoFixResults(null);
    try {
      const data = await postJson('/review', { code: codeSnippet, language });
      if (data.error) { setApiError(data.error); } else { setScanResults(data); await hydrateAdvancedModules(data.vulnerabilities || []); }
    } catch { setApiError('Failed to reach API. Make sure the backend is running.'); }
    finally { setIsScanning(false); }
  };

  const handleRepoScan = async () => {
    if (!repoUrl.trim()) { setApiError('GitHub repository URL is required for repo scan.'); return; }
    
    const jobId = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);
    
    setIsRepoScanning(true); setScanResults(null); setAttackGraph(null); setRiskRanking([]); setSimulationData(null); setApiError(null); setAutoFixResults(null);
    setScanJob({
        job_id: jobId, status: 'running', stage: 'initializing_connection', progress: 1, logs: ['Establishing background daemon...'], repo_stats: {}
    });

    const payload = { job_id: jobId, repo_url: repoUrl.trim(), branch: repoBranch.trim() || 'main', top_k: 5 };
    
    postJson('/repo-scan/start', payload).then(data => {
      if (data.error) {
         setApiError(data.error);
         setIsRepoScanning(false);
      }
    }).catch(() => {
       // We ignore POST fetch errors, primarily because serverless-offline kills the socket after 30s
       // but the daemon thread inside the simulator continues to thrive and push jobs updates!
       console.log('Backend POST proxy timeout expected, continuing to stream results...');
    });
    
    pollScanJobStatus(jobId);
  };

  const askCopilot = async () => {
    const question = chatInput.trim();
    if (!question) return;
    setChatMessages(prev => [...prev, { role: 'user', text: question }]);
    setChatInput(''); setIsChatLoading(true);
    try {
      const result = await postJson('/copilot', { code: codeSnippet, language, vulnerabilities: scanResults?.vulnerabilities || [], question });
      setChatMessages(prev => [...prev, { role: 'assistant', text: result.error || result.answer || 'No response from security copilot.' }]);
    } catch { setChatMessages(prev => [...prev, { role: 'assistant', text: 'Copilot endpoint is unreachable. Please verify backend routes.' }]); }
    finally { setIsChatLoading(false); }
  };

  useEffect(() => { chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [chatMessages]);

  const highCount = scanResults?.vulnerabilities?.filter(v => getSeverityLevel(v.severity) === 'High').length || 0;
  const mediumCount = scanResults?.vulnerabilities?.filter(v => getSeverityLevel(v.severity) === 'Medium').length || 0;
  const lowCount = scanResults?.vulnerabilities?.filter(v => getSeverityLevel(v.severity) === 'Low').length || 0;
  const score = Math.max(0, 100 - (highCount * 12 + mediumCount * 7 + lowCount * 3));
  const scoreColor = score >= 85 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444';

  const flowNodes: Node[] = useMemo(() => {
    if (!attackGraph?.nodes?.length) return [];
    return attackGraph.nodes.map((n, idx) => {
      const hue = n.criticality === 'critical' ? '#ff3333' : n.criticality === 'high' ? '#ff6a6a' : n.criticality === 'entry' ? '#9cff93' : '#79a8ff';
      return { id: n.id, position: { x: idx * 260, y: idx % 2 === 0 ? 50 : 200 }, data: { label: n.label }, style: { background: '#0d1424', color: '#E5E7EB', border: `1px solid ${hue}`, borderRadius: 12, padding: 10, minWidth: 160, boxShadow: `0 0 24px ${hue}33`, fontWeight: 700 } };
    });
  }, [attackGraph]);

  const flowEdges: Edge[] = useMemo(() => {
    if (!attackGraph?.edges?.length) return [];
    return attackGraph.edges.map(e => ({ id: e.id, source: e.source, target: e.target, label: e.label, animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#79a8ff' }, style: { stroke: '#79a8ff', strokeWidth: 2 }, labelStyle: { fill: '#dbe8ff', fontSize: 12, fontWeight: 700 }, labelBgStyle: { fill: '#0d1424', stroke: '#6e9bff', strokeWidth: 1, fillOpacity: 0.98 }, labelBgPadding: [8, 4] as [number, number], labelBgBorderRadius: 6 }));
  }, [attackGraph]);

  const tabs = [
    { id: 'results', label: 'Findings', icon: <BarChart3 className="w-4 h-4" /> },
    { id: 'attack', label: 'Attack View', icon: <Route className="w-4 h-4" /> },
    { id: 'simulation', label: 'Breach Sim', icon: <Bug className="w-4 h-4" /> },
    { id: 'copilot', label: 'AI Copilot', icon: <MessageSquare className="w-4 h-4" /> },
  ] as const;

  const inputCls = 'w-full bg-white/5 text-[#E5E7EB] rounded-xl px-4 py-3 font-mono text-sm border border-white/10 outline-none focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20 transition-all placeholder-white/30';

  return (
    <PageTransition>
      <div className="flex min-h-screen bg-[#0A0F1C] pt-16">
        {/* Sidebar */}
        <aside className="fixed left-0 top-16 h-[calc(100vh-4rem)] w-64 flex flex-col py-6 px-4 gap-4 border-r border-white/8 z-40 bg-[#0A0F1C]/95 backdrop-blur-2xl">
          <div className="px-1 mb-2">
            <p className="text-[10px] font-mono tracking-widest uppercase text-cyan-400/60 mb-1">Command Center</p>
            <p className="text-[10px] font-mono text-white/25">SageArmor Security Suite</p>
          </div>

          <div className={`${glassCard} p-5`}>
            <p className="text-[10px] uppercase tracking-widest text-white/50 mb-3">Security Score</p>
            <div className="flex items-baseline gap-2">
              <span className="text-6xl font-bold" style={{ fontFamily: 'Space Grotesk,sans-serif', color: scoreColor }}>{score}</span>
              <span className="text-white/40 text-xl">/100</span>
            </div>
            <div className="mt-3 h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.08)' }}>
              <div className="h-full rounded-full transition-all duration-700" style={{ width: `${score}%`, background: `linear-gradient(90deg, ${scoreColor}, ${scoreColor}99)` }} />
            </div>
          </div>

          <div className="space-y-3">
             <p className="text-[10px] uppercase tracking-widest text-white/50 mb-1 ml-1">Live Intelligence</p>
             {riskRanking.length > 0 ? (
               riskRanking.map(item => (
                  <div key={item.id} className="p-4 bg-white/5 border border-white/10 rounded-xl relative overflow-hidden group hover:border-cyan-500/30 transition-all">
                    <div className="absolute top-0 right-0 p-2 text-[10px] font-bold bg-white/5 rounded-bl-lg" style={{ color: getSeverityLevel(item.severity) === 'High' ? '#ef4444' : '#f59e0b' }}>
                      {item.priority_score.toFixed(1)}/10
                    </div>
                    <h4 className="text-[11px] font-bold text-white mb-2 uppercase tracking-tight pr-8">{item.issue}</h4>
                    <div className="flex gap-4">
                      <div className="text-[9px] text-gray-500 font-mono">EXPLOITABILITY: <span style={{ color: getSeverityLevel(item.severity) === 'High' ? '#ef4444' : '#f59e0b' }}>{item.exploitability.level}</span></div>
                      <div className="text-[9px] text-gray-500 font-mono">ASSET: <span style={{ color: getSeverityLevel(item.severity) === 'High' ? '#ef4444' : '#f59e0b' }}>{item.asset_value}</span></div>
                    </div>
                  </div>
               ))
             ) : (
               [
                { label: 'Critical Threats', count: highCount, color: '#ef4444' },
                { label: 'Moderate Risks', count: mediumCount, color: '#f59e0b' },
                { label: 'Minor Issues', count: lowCount, color: '#3b82f6' },
               ].map(r => (
                <div key={r.label} className="flex items-center justify-between px-3 py-2 rounded-lg" style={{ background: `${r.color}10`, borderLeft: `3px solid ${r.color}` }}>
                  <span className="text-xs text-white/70">{r.label}</span>
                  <span className="text-lg font-bold" style={{ color: r.color, fontFamily: 'Space Grotesk,sans-serif' }}>{r.count}</span>
                </div>
               ))
             )}
          </div>

          <button onClick={handleScan} disabled={isScanning}
            className="mt-auto w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-sm transition-all active:scale-95 disabled:opacity-50"
            style={{ background: 'linear-gradient(135deg,#06B6D4,#3B82F6)', color: '#fff', boxShadow: '0 0 20px rgba(6,182,212,0.4)', fontFamily: 'Space Grotesk,sans-serif' }}>
            {isScanning ? 'Scanning...' : <><Shield className="w-4 h-4" /> New Scan</>}
          </button>
        </aside>

        {/* Main content */}
        <main className="pl-64 flex-1 p-8 overflow-y-auto">
          <div className="max-w-[1200px] mx-auto space-y-6">
            <header className="mb-8">
              <h1 className="text-4xl font-bold text-white mb-2" style={{ fontFamily: 'Space Grotesk,sans-serif' }}>AI Security Dashboard</h1>
              <p className="text-white/50 text-sm">Real-time attack intelligence and vulnerability analysis.</p>
            </header>

            <div className={`${glassCard} p-6`}>
              <div className="flex justify-between items-center mb-4">
                <div className="flex items-center gap-2">
                  <Code2 className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-lg font-semibold text-white" style={{ fontFamily: 'Space Grotesk,sans-serif' }}>Snippet Scanner</h2>
                </div>
                <select value={language} onChange={e => setLanguage(e.target.value)}
                  className="bg-white/5 text-white text-xs rounded-lg px-3 py-2 border border-white/10 outline-none">
                  <option value="python" className="bg-[#0A0F1C]">Python</option>
                  <option value="javascript" className="bg-[#0A0F1C]">JavaScript</option>
                  <option value="go" className="bg-[#0A0F1C]">Go</option>
                  <option value="terraform" className="bg-[#0A0F1C]">Terraform</option>
                </select>
              </div>
              <textarea value={codeSnippet} onChange={e => setCodeSnippet(e.target.value)} spellCheck={false}
                className="w-full h-48 rounded-xl p-4 font-mono text-sm resize-none border border-white/10 outline-none focus:border-cyan-500/50 bg-black/40 text-[#E5E7EB]" />

              <div className="mt-5 pt-5 border-t border-white/8 space-y-3">
                <div className="flex items-center gap-2"><GithubIcon className="w-4 h-4 text-purple-400" /><p className="text-xs uppercase tracking-wider text-white/50">GitHub Scan</p></div>
                <input value={repoUrl} onChange={e => setRepoUrl(e.target.value)} placeholder="https://github.com/owner/repo" className={inputCls} />
                <button onClick={handleRepoScan} disabled={isRepoScanning || isScanning}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm transition-all bg-gradient-to-r from-purple-600 to-blue-600 text-white" style={{ fontFamily: 'Space Grotesk,sans-serif' }}>
                  <GithubIcon className="w-4 h-4" /> {isRepoScanning ? 'Scanning...' : 'Scan Repository'}
                </button>
              </div>
            </div>

            <div className={`${glassCard} overflow-hidden min-h-[500px]`}>
              <div className="px-6 pt-5 pb-0 border-b border-white/8 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2"><Sparkles className="w-5 h-5 text-cyan-400" /><h2 className="text-lg font-semibold text-white">Results</h2></div>
                <div className="flex gap-2 pb-4">
                  {tabs.map(tab => (
                    <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${activeTab === tab.id ? 'bg-blue-500/20 border-blue-500/40 text-blue-300' : 'bg-white/5 border-white/10 text-white/50'}`}
                      style={{ border: '1px solid' }}>
                      {tab.icon}{tab.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-6">
                {isScanning ? (
                  <div className="flex flex-col items-center justify-center h-64 gap-5">
                     <div className="w-16 h-16 rounded-full border-4 border-blue-500/20 border-t-cyan-400 animate-spin" />
                     <p className="text-white/60 animate-pulse">Running AI Security Analysis...</p>
                  </div>
                ) : apiError ? (
                  <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-sm font-mono">{apiError}</div>
                ) : isRepoScanning && !scanJob ? (
                  <div className="flex flex-col items-center justify-center h-64 gap-5">
                     <div className="w-16 h-16 rounded-full border-4 border-blue-500/20 border-t-cyan-400 animate-spin" />
                     <p className="text-white/60 animate-pulse">Initializing Progressive Repo Scan...</p>
                  </div>
                ) : (!scanResults && !scanJob) ? (
                  <div className="flex flex-col items-center justify-center h-64 text-white/30"><Code2 className="w-16 h-16 opacity-30 mb-4" /><p>Start a new scan to see results here.</p></div>
                ) : activeTab === 'results' ? (
                   <div className="space-y-6">
                     
                     {scanJob && scanJob.status !== 'completed' && scanJob.status !== 'failed' && (
                       <div className="p-5 rounded-2xl bg-[#0A0F1C]/80 border border-white/10 space-y-4 mb-2">
                         <div className="flex justify-between items-center">
                           <div className="flex items-center gap-2">
                             <div className="w-4 h-4 rounded-full border-2 border-cyan-500/30 border-t-cyan-400 animate-spin" />
                             <span className="text-sm font-bold text-cyan-400 tracking-wide uppercase">{scanJob.stage.replace('_', ' ')}</span>
                           </div>
                           <span className="text-xs font-mono text-cyan-200">{scanJob.progress}%</span>
                         </div>
                         <div className="w-full bg-white/5 rounded-full h-1.5 overflow-hidden">
                           <div className="bg-gradient-to-r from-cyan-600 to-cyan-400 h-1.5 rounded-full transition-all duration-500" style={{ width: `${scanJob.progress}%` }} />
                         </div>
                         <div className="flex flex-col gap-1">
                           {(scanJob.logs || []).slice(-2).map((log, i) => (
                             <p key={i} className={`text-xs font-mono truncate ${i === 1 ? 'text-cyan-400' : 'text-cyan-400/40'}`}>&gt; {log}</p>
                           ))}
                         </div>
                       </div>
                     )}

                     {/* AutoFix AI Global Actions */}
                     {scanResults?.vulnerabilities && scanResults.vulnerabilities.length > 0 && (!isRepoScanning) && (
                        <div className="p-6 rounded-2xl bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border border-indigo-500/20 flex flex-col md:flex-row items-center justify-between gap-6">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <Sparkles className="w-5 h-5 text-indigo-400" />
                              <h3 className="text-lg font-bold text-white" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>AutoFix AI Enabled</h3>
                            </div>
                            <p className="text-xs text-white/50">Automatically remediate detected vulnerabilities and push to GitHub.</p>
                          </div>
                          <div className="flex gap-3">
                            <button 
                              onClick={() => handleAutoFix('suggest')}
                              disabled={isAutoFixing}
                              className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white hover:bg-white/10 transition-all disabled:opacity-50"
                            >
                              🚀 Suggest Fixes
                            </button>
                            <button 
                              onClick={() => handleAutoFix('fix')}
                              disabled={isAutoFixing}
                              className="px-4 py-2 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-xs font-bold text-indigo-300 hover:bg-indigo-500/20 transition-all disabled:opacity-50"
                            >
                              🛠️ Apply Locally
                            </button>
                            <button 
                              onClick={() => handleAutoFix('pr')}
                              disabled={isAutoFixing}
                              className="px-4 py-2 rounded-xl bg-indigo-500 text-white text-xs font-bold hover:bg-indigo-400 shadow-lg shadow-indigo-500/20 transition-all disabled:opacity-50"
                            >
                              <GithubIcon className="w-3 h-3 inline mr-1" /> Create PR
                            </button>
                          </div>
                        </div>
                     )}

                     {autofixJob && autofixJob.status !== 'completed' && autofixJob.status !== 'failed' && (
                       <div className="p-5 rounded-2xl bg-[#0A0F1C]/80 border border-white/10 space-y-4">
                         <div className="flex justify-between items-center">
                           <div className="flex items-center gap-2">
                             <div className="w-4 h-4 rounded-full border-2 border-indigo-500/30 border-t-indigo-400 animate-spin" />
                             <span className="text-sm font-bold text-white tracking-wide uppercase">{autofixJob.stage.replace('_', ' ')}</span>
                           </div>
                           <span className="text-xs font-mono text-white/50">{autofixJob.progress}%</span>
                         </div>
                         <div className="w-full bg-white/5 rounded-full h-1.5 overflow-hidden">
                           <div className="bg-indigo-500 h-1.5 rounded-full transition-all duration-500" style={{ width: `${autofixJob.progress}%` }} />
                         </div>
                         <div className="flex flex-col gap-1">
                           {autofixJob.logs.slice(-2).map((log, i) => (
                             <p key={i} className={`text-xs font-mono truncate ${i === 1 ? 'text-white/70' : 'text-white/30'}`}>&gt; {log}</p>
                           ))}
                         </div>
                       </div>
                     )}

                     {autoFixResults && (
                       <div className="p-4 rounded-xl bg-green-500/5 border border-green-500/20">
                         <div className="flex items-center justify-between mb-2">
                           <div className="flex items-center gap-2">
                             <CheckCircle className="w-4 h-4 text-green-400" />
                             <p className="text-xs font-bold text-green-400 uppercase tracking-widest">AutoFix Complete</p>
                           </div>
                         </div>
                         <p className="text-sm text-white/80 mb-3">{autoFixResults.summary}</p>
                         
                         {autoFixResults.pr_url && (
                           <a href={autoFixResults.pr_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 text-xs font-bold text-cyan-400 hover:underline">
                             View Generated Pull Request <GithubIcon className="w-3 h-3" />
                           </a>
                         )}

                         {!repoUrl && autoFixResults.fixes?.filter(f => f.diff).map((snippetFix, idx) => (
                            <div key={idx} className="mt-4 p-4 bg-black/40 border border-white/5 rounded-xl">
                               <div className="flex justify-between items-center mb-3">
                                  <div className="flex items-center gap-2">
                                     <Sparkles className="w-4 h-4 text-green-300" />
                                     <span className="text-xs uppercase font-bold text-white/80">Refactored Snippet</span>
                                     <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-500/20 border border-green-500/30 text-green-300 font-mono tracking-wide">CONFIDENCE: {snippetFix.confidence?.toUpperCase() || 'HIGH'}</span>
                                     {snippetFix.patch_status === 'verified' ? (
                                       <span className="text-[10px] px-2 py-0.5 rounded-full bg-green-500/20 border border-green-500/30 text-green-300 font-mono tracking-wide">🛡️ Verified Patch</span>
                                     ) : (
                                       <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-300 font-mono tracking-wide">⚠️ Unverified Draft</span>
                                     )}
                                  </div>
                                  <button onClick={() => { navigator.clipboard.writeText(snippetFix.fixed_code); setCopiedIdx(-1); setTimeout(() => setCopiedIdx(null), 2000) }} className="text-[10px] font-bold px-3 py-1.5 bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/20 rounded-lg transition-all">
                                     {copiedIdx === -1 ? 'Copied to Clipboard!' : 'Copy Fixed Code'}
                                  </button>
                               </div>
                               <p className="text-xs text-white/60 mb-3 leading-relaxed whitespace-pre-wrap">{snippetFix.explanation}</p>
                               {snippetFix.verification_gates && (
                                 <details className="mb-3">
                                   <summary className="text-[10px] text-cyan-400/80 cursor-pointer uppercase font-mono tracking-wider">🔬 Verification Gate Details</summary>
                                   <div className="mt-2 p-3 bg-black/60 rounded-lg border border-white/5 space-y-1 font-mono text-[11px]">
                                     {snippetFix.verification_gates.map((g: any, gi: number) => (
                                       <div key={gi} className={g.passed ? 'text-green-400' : 'text-red-400'}>
                                         {g.passed ? '✅' : '❌'} {g.gate}: {g.detail}
                                       </div>
                                     ))}
                                   </div>
                                 </details>
                               )}
                               <div className="rounded-lg overflow-hidden border border-white/5">
                                 <pre className="text-[11px] font-mono p-4 bg-[#0A0F1C] overflow-x-auto">
                                    {snippetFix.diff.split('\n').map((line: string, lIdx: number) => {
                                        if (line.startsWith('---') || line.startsWith('+++')) return null;
                                        const isAdd = line.startsWith('+');
                                        const isDel = line.startsWith('-');
                                        const isHeader = line.startsWith('@@');
                                        return (
                                           <div key={lIdx} className={`px-2 py-0.5 ${isAdd ? 'bg-green-500/10 text-green-300' : isDel ? 'bg-red-500/10 text-red-300' : isHeader ? 'text-cyan-500/50' : 'text-white/60'}`}>
                                             {line}
                                           </div>
                                        );
                                    })}
                                 </pre>
                               </div>
                            </div>
                         ))}
                       </div>
                     )}

                     {scanResults?.vulnerabilities?.map((v, i) => {
                       const { card, badge, iconColor, IconComp, accent } = sevStyle(getSeverityLevel(v.severity));
                       return (
                         <div key={i} className={`rounded-2xl border p-6 ${card} backdrop-blur-md`}>
                           <div className="flex gap-5">
                             <div className={`p-3 rounded-xl bg-${accent}-500/10 h-min mt-1`}>
                                <IconComp className={`w-6 h-6 ${iconColor}`} />
                             </div>
                             
                             <div className="flex-1">
                               <div className="flex items-center justify-between mb-2">
                                 <h3 className="text-lg font-bold text-white" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>{v.issue}</h3>
                                 <div className="flex items-center gap-2">
                                   <span className="text-[10px] uppercase font-mono text-white/30 mr-2">{v.file_path || ''}</span>
                                   {v.verified ? (
                                     <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-green-500/20 border border-green-500/30 text-green-300">🛡️ Verified</span>
                                   ) : (
                                     <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-300">⚠️ Unconfirmed</span>
                                   )}
                                   <span className={`text-[10px] font-bold px-3 py-1 rounded-full ${badge} uppercase tracking-wider`}>{v.severity}</span>
                                 </div>
                               </div>
                               
                               <p className="text-sm text-white/70 leading-relaxed mb-6">{v.explanation}</p>
                               
                               <div className="mb-6 p-4 bg-red-950/20 border border-red-900/30 rounded-xl">
                                  <div className="flex items-center gap-2 mb-3">
                                     <Bug className="w-4 h-4 text-red-400" />
                                     <span className="text-[10px] font-bold text-red-400 uppercase tracking-widest">Simulated Attack Scenario</span>
                                  </div>
                                  <p className="text-xs text-white/60 mb-2 leading-relaxed italic">
                                    {v.poc_exploit_scenario || `An attacker could use a crafted payload against the ${v.attack_vector || 'input field'} to trigger this vulnerability and gain unauthorized access.`}
                                  </p>
                               </div>

                               <div className="p-4 bg-cyan-950/10 border border-cyan-900/30 rounded-xl relative group">
                                  <div className="flex items-center justify-between mb-3">
                                    <div className="flex items-center gap-2">
                                      <CheckCircle className="w-4 h-4 text-cyan-400" />
                                      <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest">Suggested Fix</span>
                                    </div>
                                    <button onClick={() => handleCopyFix(v, i)} className="text-[10px] text-cyan-400 hover:text-cyan-300 bg-cyan-400/10 px-2 py-1 rounded-lg transition-all">
                                      {copiedIdx === i ? 'Copied!' : 'Copy Fix'}
                                    </button>
                                  </div>
                                  <div className="bg-black/60 rounded-lg p-4 border border-white/5 mb-3">
                                    <pre className="text-xs font-mono text-cyan-300/80 overflow-x-auto whitespace-pre-wrap">
                                      {v.remediation?.patch || v.suggested_fix || '// Secure implementation here...'}
                                    </pre>
                                  </div>
                               </div>

                               {v.dynamic_trace && (
                                 <details className="mt-3">
                                   <summary className="text-[10px] text-cyan-400/70 hover:text-cyan-300 cursor-pointer uppercase tracking-widest font-mono">
                                     🔬 Sandbox Execution Trace
                                   </summary>
                                   <div className="mt-2 p-3 bg-black/60 rounded-lg border border-white/5 font-mono text-[11px] space-y-1">
                                     <div className="text-cyan-400">Sink Reached: {v.dynamic_trace.sink_reached ? 'YES ✅' : 'NO ⛔'}</div>
                                     {v.dynamic_trace.sink_line && <div className="text-white/60">Sink Line: {v.dynamic_trace.sink_line}</div>}
                                     {v.dynamic_trace.vector_used && <div className="text-orange-400">Vector: {v.dynamic_trace.vector_used}</div>}
                                     {v.dynamic_trace.executed_lines && (
                                       <div className="text-white/40">Executed: {Array.isArray(v.dynamic_trace.executed_lines) ? v.dynamic_trace.executed_lines.join(', ') : String(v.dynamic_trace.executed_lines)}</div>
                                     )}
                                     {v.dynamic_trace.harness_output && (
                                       <pre className="mt-1 p-2 bg-black/80 rounded text-[10px] text-white/50 whitespace-pre-wrap">{v.dynamic_trace.harness_output}</pre>
                                     )}
                                   </div>
                                 </details>
                               )}
                             </div>
                           </div>
                         </div>
                       );
                     })}
                   </div>
                ) : activeTab === 'attack' ? (
                   <div className="relative h-[400px] bg-black/20 rounded-xl overflow-hidden border border-white/10">
                     {attackGraph?.ast_derived && (
                       <div className="absolute top-2 right-2 z-10 text-[10px] text-green-400 font-mono px-3 py-1 bg-green-500/10 border border-green-500/20 rounded-lg">
                         🌳 AST-Derived Graph
                       </div>
                     )}
                     <ReactFlow nodes={flowNodes} edges={flowEdges} fitView proOptions={{ hideAttribution: true }}>
                       <Background gap={20} size={1} color="#333" />
                       <Controls />
                     </ReactFlow>
                   </div>
                ) : activeTab === 'simulation' ? (
                   <div className="space-y-4">
                     <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4">
                       <p className="text-red-400 text-xs font-bold mb-2 uppercase">Attack Chain</p>
                       <p className="text-white/80">{simulationData?.chain_summary || 'No breach data available.'}</p>
                     </div>
                     <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-white/5 border border-white/10 rounded-xl">
                          <p className="text-white/40 text-xs mb-2 uppercase">Exposed Assets</p>
                          {simulationData?.accessible_data?.map(d => <div key={d} className="text-sm text-white/80 flex gap-2"><span className="text-red-400">•</span>{d}</div>)}
                        </div>
                        <div className="p-4 bg-white/5 border border-white/10 rounded-xl">
                          <p className="text-white/40 text-xs mb-2 uppercase">Business Impact</p>
                          {simulationData?.likely_impact?.map(d => <div key={d} className="text-sm text-white/80 flex gap-2"><span className="text-orange-400">•</span>{d}</div>)}
                        </div>
                     </div>
                   </div>
                ) : (
                  <div className="flex flex-col h-[400px]">
                    <div className="flex-1 overflow-y-auto space-y-4 mb-4 pr-2">
                       {chatMessages.map((m, i) => (
                         <div key={i} className={`p-3 rounded-xl max-w-[80%] text-sm ${m.role === 'user' ? 'ml-auto bg-blue-500/20 border border-blue-500/30' : 'mr-auto bg-white/5 border border-white/10'}`}>
                           {m.text}
                         </div>
                       ))}
                       {isChatLoading && <div className="text-white/30 text-xs animate-pulse">Assistant is thinking...</div>}
                       <div ref={chatBottomRef} />
                    </div>
                    <div className="flex gap-2">
                       <input value={chatInput} onChange={e => setChatInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && askCopilot()} placeholder="Ask security questions..." className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm text-white focus:border-cyan-500/50 outline-none" />
                       <button onClick={askCopilot} className="bg-cyan-500 hover:bg-cyan-400 text-white p-2 rounded-xl transition-all"><Send className="w-5 h-5" /></button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    </PageTransition>
  );
}
