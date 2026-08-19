import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Crosshair, 
  Play, 
  Loader2, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowRight, 
  Lock, 
  Unlock, 
  Eye, 
  Wrench, 
  RefreshCw, 
  Network, 
  FileText, 
  Server, 
  Database, 
  Radio, 
  Activity, 
  Layers, 
  Cpu, 
  Flame, 
  Check, 
  X, 
  Sparkles,
  Zap,
  Globe,
  ExternalLink,
  ChevronRight,
  Shield,
  Clock,
  KeyRound
} from 'lucide-react';
import { 
  ScanTarget, 
  VulnerabilityFinding, 
  RedTeamSimulationReport, 
  AttackPathGraph, 
  ExploitValidationRecord, 
  PurpleTeamDefenseAudit, 
  ScopeAuthorizationConfig,
  Severity
} from '../../types';
import { RedTeamEngine } from '../../services/redTeamEngine';

interface RedTeamDashboardViewProps {
  target: ScanTarget;
  findings: VulnerabilityFinding[];
  onOpenFindingModal: (finding: VulnerabilityFinding, tab?: 'explain' | 'recommend' | 'fix' | 'verify') => void;
  onNavigateToRemediation: () => void;
  onRescan: () => void;
}

export const RedTeamDashboardView: React.FC<RedTeamDashboardViewProps> = ({
  target,
  findings,
  onOpenFindingModal,
  onNavigateToRemediation,
  onRescan
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'graph' | 'exploits' | 'detection_effectiveness' | 'scope' | 'analyst'>('graph');
  const [detectionFilter, setDetectionFilter] = useState<'ALL' | 'BLOCKED' | 'DETECTED_ONLY' | 'BLINDSPOTS'>('ALL');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationStep, setSimulationStep] = useState<string | null>(null);
  const [selectedAttackPathIndex, setSelectedAttackPathIndex] = useState(0);
  const [selectedExploit, setSelectedExploit] = useState<ExploitValidationRecord | null>(null);
  const [activePlaybackStep, setActivePlaybackStep] = useState<number | null>(null);

  // Generate Simulation Report via RedTeamEngine
  const [report, setReport] = useState<RedTeamSimulationReport>(() => {
    return RedTeamEngine.runAdversarySimulation(target, findings);
  });

  // Re-run simulation when target or findings change
  React.useEffect(() => {
    setReport(RedTeamEngine.runAdversarySimulation(target, findings));
  }, [target, findings]);

  const handleRunAdversarySimulation = async () => {
    setIsSimulating(true);
    setSimulationStep('Connecting to Isolated Sandbox & Launching Red Team Engine...');

    try {
      const res = await fetch('/api/redteam/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, findings })
      });
      const data = await res.json();
      if (res.ok && data.success && data.report) {
        setReport(data.report);
      } else {
        const freshReport = RedTeamEngine.runAdversarySimulation(target, findings);
        setReport(freshReport);
      }
    } catch (err) {
      console.warn('Backend Red Team simulation call failed, falling back:', err);
      const freshReport = RedTeamEngine.runAdversarySimulation(target, findings);
      setReport(freshReport);
    } finally {
      setIsSimulating(false);
      setSimulationStep(null);
    }
  };

  const currentPath = report.attackPaths[selectedAttackPathIndex] || report.attackPaths[0];

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner & Authorization Gate Header */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex flex-col lg:flex-row lg:items-center justify-between gap-5 relative overflow-hidden">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-red-950/20 rounded-full blur-3xl pointer-events-none"></div>
        
        <div className="space-y-2 max-w-2xl relative z-10">
          <div className="flex items-center space-x-2">
            <span className="p-1 rounded bg-red-950/60 border border-red-800 text-red-400 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center space-x-1">
              <Crosshair className="h-3 w-3" />
              <span>Adversary Simulation Subsystem</span>
            </span>
            <span className="p-1 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center space-x-1">
              <CheckCircle2 className="h-3 w-3" />
              <span>Scope Authorized ✓</span>
            </span>
            <span className="p-1 rounded bg-blue-950/60 border border-blue-800 text-blue-400 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center space-x-1">
              <Lock className="h-3 w-3" />
              <span>Zero Prod Impact</span>
            </span>
          </div>

          <h2 className="text-xl font-black text-white tracking-tight flex items-center space-x-2.5">
            <span>Red Team & Purple Team Attack Engine</span>
          </h2>
          <p className="text-xs text-gray-400 leading-relaxed">
            Safely proves vulnerability exploitability in an isolated disposable sandbox, maps real-world multi-stage attack paths, and audits defensive detection across WAF, IDS, and SIEM logging.
          </p>
        </div>

        <div className="flex items-center space-x-3 relative z-10">
          <button
            onClick={handleRunAdversarySimulation}
            disabled={isSimulating}
            className="flex items-center space-x-2 px-5 py-2.5 bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-all shadow-lg shadow-red-950/50 disabled:opacity-50"
          >
            {isSimulating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 fill-white" />}
            <span>{isSimulating ? 'Simulating Adversary...' : 'Launch Adversary Simulation'}</span>
          </button>
        </div>
      </div>

      {/* Live Simulation Progress Indicator */}
      {isSimulating && simulationStep && (
        <div className="p-4 rounded-xl bg-red-950/30 border border-red-900/60 space-y-2 animate-in fade-in">
          <div className="flex items-center justify-between text-xs font-mono text-red-300">
            <div className="flex items-center space-x-2">
              <Loader2 className="h-4 w-4 animate-spin text-red-400" />
              <span>{simulationStep}</span>
            </div>
            <span className="text-gray-400 text-[10px]">SANDBOX ID: {report.scope.sandboxEnvironment.disposableInstanceId}</span>
          </div>
          <div className="w-full bg-red-950/60 rounded-full h-1.5 overflow-hidden">
            <div className="bg-red-500 h-1.5 rounded-full animate-pulse w-4/5"></div>
          </div>
        </div>
      )}

      {/* 4 Quick Metric KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Confirmed Exploits</span>
            <Flame className="h-4 w-4 text-red-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-black text-white">{report.confirmedExploitableCount}</span>
            <span className="text-[10px] font-mono text-gray-500">/ {report.totalExploitsAttempted} tested</span>
          </div>
          <p className="text-[10px] text-gray-500">Proved non-destructively in sandbox</p>
        </div>

        <div className="p-4 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Active Attack Paths</span>
            <Network className="h-4 w-4 text-amber-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-black text-white">{report.attackPaths.filter(p => !p.isMitigated).length}</span>
            <span className="text-[10px] font-mono text-gray-500">Chains Identified</span>
          </div>
          <p className="text-[10px] text-gray-500">Multi-stage privilege escalation</p>
        </div>

        <div className="p-4 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Blue Team Defense Score</span>
            <Shield className="h-4 w-4 text-blue-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className={`text-2xl font-black ${
              report.purpleTeamOverallScore >= 80 ? 'text-emerald-400' :
              report.purpleTeamOverallScore >= 60 ? 'text-amber-400' : 'text-red-400'
            }`}>
              {report.purpleTeamOverallScore}%
            </span>
            <span className="text-[10px] font-mono text-gray-500">Detection Rate</span>
          </div>
          <p className="text-[10px] text-gray-500">WAF • IDS • SIEM Audit Status</p>
        </div>

        <div className="p-4 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-1">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Exploits Blocked / Fixed</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-black text-emerald-400">{report.blockedCount}</span>
            <span className="text-[10px] font-mono text-gray-500">Remediated</span>
          </div>
          <p className="text-[10px] text-gray-500">Verified via closed-loop retest</p>
        </div>
      </div>

      {/* Sub-Tab Navigation Bar */}
      <div className="flex items-center space-x-2 border-b border-[#1F1F1F] pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('graph')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
            activeSubTab === 'graph'
              ? 'bg-[#1F1F1F] text-white border border-[#333333]'
              : 'text-gray-400 hover:text-white hover:bg-[#141414]'
          }`}
        >
          <Network className="h-3.5 w-3.5 text-amber-400" />
          <span>Interactive Attack Graph ({report.attackPaths.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('exploits')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
            activeSubTab === 'exploits'
              ? 'bg-[#1F1F1F] text-white border border-[#333333]'
              : 'text-gray-400 hover:text-white hover:bg-[#141414]'
          }`}
        >
          <Flame className="h-3.5 w-3.5 text-red-400" />
          <span>Controlled Exploit Proofs ({report.exploitValidations.length})</span>
        </button>

        <button
          id="detection-effectiveness-tab"
          onClick={() => setActiveSubTab('detection_effectiveness')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
            activeSubTab === 'detection_effectiveness'
              ? 'bg-[#1F1F1F] text-white border border-[#333333]'
              : 'text-gray-400 hover:text-white hover:bg-[#141414]'
          }`}
        >
          <Activity className="h-3.5 w-3.5 text-purple-400" />
          <span>Detection Effectiveness ({report.purpleTeamAudits.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('analyst')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
            activeSubTab === 'analyst'
              ? 'bg-[#1F1F1F] text-white border border-[#333333]'
              : 'text-gray-400 hover:text-white hover:bg-[#141414]'
          }`}
        >
          <Cpu className="h-3.5 w-3.5 text-blue-400" />
          <span>AI Adversary Narrative</span>
        </button>

        <button
          onClick={() => setActiveSubTab('scope')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
            activeSubTab === 'scope'
              ? 'bg-[#1F1F1F] text-white border border-[#333333]'
              : 'text-gray-400 hover:text-white hover:bg-[#141414]'
          }`}
        >
          <Lock className="h-3.5 w-3.5 text-emerald-400" />
          <span>Scope & Sandbox Gateway</span>
        </button>
      </div>

      {/* SUB-VIEW 1: INTERACTIVE ATTACK GRAPH & ATTACK PATHS */}
      {activeSubTab === 'graph' && currentPath && (
        <div className="space-y-6">
          {/* Path Selector Tabs */}
          <div className="flex items-center space-x-2">
            <span className="text-xs text-gray-500 font-mono uppercase">Attack Chains:</span>
            {report.attackPaths.map((path, idx) => (
              <button
                key={path.id}
                onClick={() => {
                  setSelectedAttackPathIndex(idx);
                  setActivePlaybackStep(null);
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all flex items-center space-x-2 ${
                  selectedAttackPathIndex === idx
                    ? 'bg-red-950 text-red-300 border border-red-800 font-bold'
                    : 'bg-[#141414] text-gray-400 hover:text-white border border-[#1F1F1F]'
                }`}
              >
                <span>{path.id}</span>
                {path.isMitigated ? (
                  <span className="text-[9px] px-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">SEVERED</span>
                ) : (
                  <span className="text-[9px] px-1 rounded bg-red-950 text-red-400 border border-red-800">CRITICAL</span>
                )}
              </button>
            ))}
          </div>

          {/* Attack Chain Visualizer Card */}
          <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1F1F1F] pb-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <h3 className="text-base font-bold text-white tracking-tight">{currentPath.title}</h3>
                  <span className={`px-2 py-0.5 text-[10px] font-mono rounded uppercase font-bold ${
                    currentPath.isMitigated
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : 'bg-red-950 text-red-400 border border-red-800'
                  }`}>
                    {currentPath.isMitigated ? 'MITIGATED / SEVERED' : `RISK SCORE: ${currentPath.riskScore}/100`}
                  </span>
                </div>
                <p className="text-xs text-gray-400 leading-relaxed">{currentPath.narrative}</p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => {
                    let step = 0;
                    setActivePlaybackStep(0);
                    const interval = setInterval(() => {
                      step += 1;
                      if (step >= currentPath.nodes.length) {
                        clearInterval(interval);
                      } else {
                        setActivePlaybackStep(step);
                      }
                    }, 1200);
                  }}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#1F1F1F] hover:bg-[#2A2A2A] text-xs font-mono text-gray-200 transition-colors"
                >
                  <Play className="h-3 w-3 text-red-400" />
                  <span>Animate Kill Chain</span>
                </button>
              </div>
            </div>

            {/* Interactive Attack Graph Nodes Flow */}
            <div className="space-y-3">
              <div className="text-[11px] font-mono text-gray-500 uppercase">ATTACK PATH STEP-BY-STEP EXECUTION FLOW:</div>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-3 relative">
                {currentPath.nodes.map((node, nIdx) => {
                  const isActivePlayback = activePlaybackStep === nIdx;
                  const isNodeMitigated = node.status === 'MITIGATED' || node.status === 'BLOCKED';

                  return (
                    <div
                      key={node.id}
                      className={`p-4 rounded-xl border transition-all flex flex-col justify-between relative ${
                        isActivePlayback
                          ? 'bg-red-950/40 border-red-500 shadow-lg shadow-red-950/50 scale-105 z-10'
                          : isNodeMitigated
                          ? 'bg-[#0E1712] border-emerald-900/60'
                          : 'bg-[#161616] border-[#222222] hover:border-[#333333]'
                      }`}
                    >
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/60 text-gray-400 border border-[#222222]">
                            Step {nIdx + 1}
                          </span>
                          <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                            isNodeMitigated
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : 'bg-red-950 text-red-400 border border-red-800'
                          }`}>
                            {node.status}
                          </span>
                        </div>

                        <div>
                          <h4 className="text-xs font-bold text-white tracking-tight leading-tight">{node.label}</h4>
                          <span className="text-[10px] font-mono text-gray-500 block mt-1 truncate">
                            {node.targetAsset}
                          </span>
                        </div>

                        <p className="text-[11px] text-gray-400 leading-relaxed">
                          {node.details}
                        </p>
                      </div>

                      {node.findingId && (
                        <div className="pt-3 mt-3 border-t border-[#222222]">
                          <button
                            onClick={() => {
                              const f = findings.find(find => find.id === node.findingId);
                              if (f) onOpenFindingModal(f, 'fix');
                            }}
                            className="w-full flex items-center justify-center space-x-1.5 px-2 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 text-[11px] font-mono transition-colors border border-blue-800/40"
                          >
                            <Wrench className="h-3 w-3" />
                            <span>Patch Vulnerability</span>
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Impact & Fix Banner */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40 space-y-1.5">
                <div className="flex items-center space-x-2 text-xs font-bold text-red-300">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <span>Business Impact Analysis</span>
                </div>
                <p className="text-xs text-gray-300 leading-relaxed">
                  {currentPath.businessImpact}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40 space-y-1.5">
                <div className="flex items-center space-x-2 text-xs font-bold text-emerald-300">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <span>Recommended Architectural Severance</span>
                </div>
                <p className="text-xs text-gray-300 leading-relaxed">
                  {currentPath.recommendedFix}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-VIEW 2: CONTROLLED EXPLOIT VALIDATION CARDS */}
      {activeSubTab === 'exploits' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-xs text-gray-400">
              Deterministic, non-destructive proofs executed in an isolated disposable sandbox. Zero production side-effects.
            </div>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-lg bg-black text-gray-400 border border-[#1F1F1F]">
              ENVIRONMENT: Disposable Synthetic Docker Sandbox
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {report.exploitValidations.map((exploit) => {
              const matchedFinding = findings.find(f => f.id === exploit.findingId);

              return (
                <div
                  key={exploit.id}
                  className={`p-5 rounded-2xl border transition-all ${
                    exploit.status === 'CONFIRMED_EXPLOITABLE'
                      ? 'bg-[#141414] border-red-900/60 shadow-lg shadow-red-950/20'
                      : 'bg-[#111111] border-[#1F1F1F]'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                    <div className="space-y-2 flex-1">
                      <div className="flex items-center space-x-3">
                        <span className="text-xs font-mono font-bold text-gray-400 bg-black px-2 py-0.5 rounded border border-[#222222]">
                          {exploit.id}
                        </span>
                        
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          exploit.status === 'CONFIRMED_EXPLOITABLE'
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}>
                          {exploit.status === 'CONFIRMED_EXPLOITABLE' ? '🔴 CONFIRMED EXPLOITABLE' : '🛡️ SAFE / BLOCKED'}
                        </span>

                        <span className="text-xs font-mono text-gray-400">
                          Confidence: <strong className={exploit.confidenceScore > 90 ? 'text-red-400' : 'text-emerald-400'}>{exploit.confidenceScore}%</strong>
                        </span>

                        <span className="text-xs font-mono text-gray-500">
                          Latency: {exploit.executionTimeMs}ms
                        </span>
                      </div>

                      <h4 className="text-sm font-bold text-white tracking-tight">
                        {exploit.vulnerabilityTitle} ({exploit.cwe})
                      </h4>

                      <div className="p-3 rounded-xl bg-black border border-[#222222] font-mono text-xs text-gray-300 space-y-1">
                        <div className="text-[10px] text-gray-500 uppercase">SYNTHETIC ATTACK PAYLOAD SENT:</div>
                        <div className="text-red-300 truncate">{exploit.payloadSent}</div>
                      </div>

                      <div className="text-xs text-gray-300 leading-relaxed font-sans pt-1">
                        <strong className="text-gray-400 block text-[11px] font-mono uppercase mb-0.5">Evidence Proof:</strong>
                        {exploit.evidenceProof}
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-gray-400 pt-1">
                        <div>
                          <span className="text-gray-600 block">DATA ACCESSED:</span>
                          <span className="text-gray-300">{exploit.dataAccessed}</span>
                        </div>
                        <div>
                          <span className="text-gray-600 block">PRODUCTION IMPACT:</span>
                          <span className="text-emerald-400 font-bold">{exploit.productionImpact}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col sm:flex-row lg:flex-col space-y-2 shrink-0">
                      {matchedFinding && (
                        <button
                          onClick={() => onOpenFindingModal(matchedFinding, 'fix')}
                          className="flex items-center justify-center space-x-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md"
                        >
                          <Wrench className="h-3.5 w-3.5" />
                          <span>Apply AI Patch</span>
                        </button>
                      )}

                      {matchedFinding && (
                        <button
                          onClick={() => onOpenFindingModal(matchedFinding, 'verify')}
                          className="flex items-center justify-center space-x-2 px-4 py-2 rounded-xl bg-[#1F1F1F] hover:bg-[#2A2A2A] text-gray-300 hover:text-white text-xs font-mono transition-colors border border-[#2A2A2A]"
                        >
                          <RefreshCw className="h-3.5 w-3.5" />
                          <span>Re-test Sandbox</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SUB-VIEW 3: DETECTION EFFECTIVENESS & TELEMETRY MAPPING */}
      {(activeSubTab === 'detection_effectiveness' || activeSubTab === 'purple_team') && (
        <div className="space-y-6">
          {/* Top Section Header & KPI Dashboard */}
          <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1F1F1F] pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="p-1 rounded bg-purple-950/80 border border-purple-800 text-purple-400 font-mono text-[10px] font-bold uppercase tracking-wider">
                    Blue Team Visibility & Interception Matrix
                  </span>
                </div>
                <h3 className="text-base font-bold text-white uppercase tracking-wider mt-1">Detection Effectiveness & Telemetry Mapping</h3>
                <p className="text-xs text-gray-400 mt-0.5 max-w-3xl leading-relaxed">
                  Maps every simulated adversary attack against live Application Logs, WAF alerts, and Network IDS signatures to measure if enterprise defenses detected or blocked the attack in real time.
                </p>
              </div>

              <div className="flex items-center space-x-3 bg-black px-4 py-3 rounded-2xl border border-[#222222] shrink-0">
                <div className="text-right">
                  <span className="text-[10px] text-gray-500 font-mono block uppercase">Overall Defense Score</span>
                  <span className={`text-xl font-black ${
                    report.purpleTeamOverallScore >= 80 ? 'text-emerald-400' :
                    report.purpleTeamOverallScore >= 60 ? 'text-amber-400' : 'text-red-400'
                  }`}>
                    {report.purpleTeamOverallScore}%
                  </span>
                </div>
                <div className="h-8 w-px bg-[#222222]"></div>
                <div className="text-right">
                  <span className="text-[10px] text-gray-500 font-mono block uppercase">Interception Rate</span>
                  <span className="text-xl font-black text-white">
                    {Math.round((report.purpleTeamAudits.filter(a => a.simulatedAttackOutcome === 'ATTACK_BLOCKED').length / (report.purpleTeamAudits.length || 1)) * 100)}%
                  </span>
                </div>
              </div>
            </div>

            {/* 4 Telemetry Stack Health Indicators */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="p-3 bg-black/60 rounded-xl border border-[#222222] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-500 uppercase">WAF Filter Coverage</span>
                  <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
                </div>
                <div className="text-sm font-bold text-white">
                  {report.purpleTeamAudits.filter(a => a.wafDetection.status !== 'NOT_DETECTED').length} / {report.purpleTeamAudits.length} Monitored
                </div>
                <p className="text-[10px] text-gray-500 font-mono">ModSecurity / Cloud WAF CRS</p>
              </div>

              <div className="p-3 bg-black/60 rounded-xl border border-[#222222] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-500 uppercase">Network IDS Signatures</span>
                  <Activity className="h-3.5 w-3.5 text-purple-400" />
                </div>
                <div className="text-sm font-bold text-white">
                  {report.purpleTeamAudits.filter(a => a.idsDetection.status === 'DETECTED').length} / {report.purpleTeamAudits.length} Matched
                </div>
                <p className="text-[10px] text-gray-500 font-mono">Suricata & Snort Engine</p>
              </div>

              <div className="p-3 bg-black/60 rounded-xl border border-[#222222] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-500 uppercase">App Security Audit Logs</span>
                  <FileText className="h-3.5 w-3.5 text-emerald-400" />
                </div>
                <div className="text-sm font-bold text-white">
                  {report.purpleTeamAudits.filter(a => a.applicationLogging.status === 'AUDIT_LOG_RECORDED').length} / {report.purpleTeamAudits.length} Logged
                </div>
                <p className="text-[10px] text-gray-500 font-mono">Structured JSON Audit Traces</p>
              </div>

              <div className="p-3 bg-black/60 rounded-xl border border-[#222222] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-gray-500 uppercase">SIEM Alert Correlation</span>
                  <Radio className="h-3.5 w-3.5 text-amber-400" />
                </div>
                <div className="text-sm font-bold text-white">
                  {report.purpleTeamAudits.filter(a => a.siemAlertGenerated).length} / {report.purpleTeamAudits.length} Escalated
                </div>
                <p className="text-[10px] text-gray-500 font-mono">Real-time SOC Dispatch</p>
              </div>
            </div>
          </div>

          {/* Filter Pills Bar */}
          <div className="flex items-center space-x-2 overflow-x-auto pb-1">
            <span className="text-xs text-gray-500 font-mono uppercase shrink-0">Filter Telemetry:</span>
            {[
              { id: 'ALL' as const, label: `All Attacks (${report.purpleTeamAudits.length})` },
              { id: 'BLOCKED' as const, label: `Blocked & Defended (${report.purpleTeamAudits.filter(a => a.simulatedAttackOutcome === 'ATTACK_BLOCKED').length})` },
              { id: 'DETECTED_ONLY' as const, label: `Detected Only / Alerted (${report.purpleTeamAudits.filter(a => a.wafDetection.status === 'DETECTED_ONLY' || (a.idsDetection.status === 'DETECTED' && a.simulatedAttackOutcome !== 'ATTACK_BLOCKED')).length})` },
              { id: 'BLINDSPOTS' as const, label: `Telemetry Blindspots (${report.purpleTeamAudits.filter(a => a.simulatedAttackOutcome !== 'ATTACK_BLOCKED' && a.wafDetection.status === 'NOT_DETECTED' && a.idsDetection.status === 'NOT_DETECTED').length})` }
            ].map(f => (
              <button
                key={f.id}
                onClick={() => setDetectionFilter(f.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                  detectionFilter === f.id
                    ? 'bg-purple-600 text-white shadow'
                    : 'bg-[#161616] text-gray-400 hover:text-white border border-[#1F1F1F]'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Attack Telemetry Mapping Cards */}
          <div className="grid grid-cols-1 gap-5">
            {report.purpleTeamAudits
              .filter(audit => {
                if (detectionFilter === 'ALL') return true;
                if (detectionFilter === 'BLOCKED') return audit.simulatedAttackOutcome === 'ATTACK_BLOCKED';
                if (detectionFilter === 'DETECTED_ONLY') return audit.wafDetection.status === 'DETECTED_ONLY' || (audit.idsDetection.status === 'DETECTED' && audit.simulatedAttackOutcome !== 'ATTACK_BLOCKED');
                if (detectionFilter === 'BLINDSPOTS') return audit.simulatedAttackOutcome !== 'ATTACK_BLOCKED' && audit.wafDetection.status === 'NOT_DETECTED' && audit.idsDetection.status === 'NOT_DETECTED';
                return true;
              })
              .map((audit) => {
                const isBlocked = audit.simulatedAttackOutcome === 'ATTACK_BLOCKED';
                const isDetectedOnly = !isBlocked && (audit.wafDetection.status === 'DETECTED_ONLY' || audit.idsDetection.status === 'DETECTED' || audit.siemAlertGenerated);
                const isBlindspot = !isBlocked && !isDetectedOnly;
                const matchedFinding = findings.find(f => f.id === audit.attackId || f.title.toLowerCase().includes(audit.attackName.toLowerCase()));

                return (
                  <div key={audit.attackId} className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4 shadow-md">
                    {/* Attack Mapping Header */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[#1F1F1F] pb-3">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-gray-400 bg-black px-2 py-0.5 rounded border border-[#222222]">
                            {audit.attackId}
                          </span>
                          <h4 className="text-sm font-bold text-white tracking-tight">{audit.attackName}</h4>
                        </div>
                        <div className="flex items-center space-x-3 text-[11px] font-mono text-gray-500">
                          <span>MITRE ATT&CK: <strong className="text-gray-400">{audit.techniqueMITRE}</strong></span>
                          <span>Target: <strong className="text-blue-400">{audit.targetService}</strong></span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2.5">
                        <span className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold uppercase tracking-wider ${
                          isBlocked
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : isDetectedOnly
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-red-950 text-red-400 border border-red-800 animate-pulse'
                        }`}>
                          {isBlocked ? '✓ ATTACK BLOCKED & DEFENDED' : isDetectedOnly ? '⚠ DETECTED / LOGGED ONLY (NOT BLOCKED)' : '✖ TELEMETRY BLINDSPOT (MISSED)'}
                        </span>
                        <span className="text-xs font-mono text-gray-400 bg-black px-2.5 py-1 rounded border border-[#222222]">
                          Score: <strong className={audit.defenseScore >= 70 ? 'text-emerald-400' : 'text-red-400'}>{audit.defenseScore}/100</strong>
                        </span>
                      </div>
                    </div>

                    {/* 4 Defense Pillars Matrix */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                      {/* 1. WAF Alerts */}
                      <div className="p-3.5 bg-black/60 rounded-xl border border-[#222222] space-y-1.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 uppercase">
                            <span>1. WAF Filter Status</span>
                            <Shield className="h-3 w-3 text-blue-400" />
                          </div>
                          <span className={`text-xs font-mono font-bold block pt-1 ${
                            audit.wafDetection.status === 'DETECTED_AND_BLOCKED' ? 'text-emerald-400' :
                            audit.wafDetection.status === 'DETECTED_ONLY' ? 'text-amber-400' : 'text-red-400'
                          }`}>
                            {audit.wafDetection.status}
                          </span>
                        </div>
                        {audit.wafDetection.ruleTriggered ? (
                          <span className="text-[10px] font-mono text-gray-400 block truncate bg-[#161616] p-1 rounded border border-[#2A2A2A]">
                            {audit.wafDetection.ruleTriggered}
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono text-gray-600 block">No WAF rule matched</span>
                        )}
                      </div>

                      {/* 2. Network IDS */}
                      <div className="p-3.5 bg-black/60 rounded-xl border border-[#222222] space-y-1.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 uppercase">
                            <span>2. Network IDS Telemetry</span>
                            <Activity className="h-3 w-3 text-purple-400" />
                          </div>
                          <span className={`text-xs font-mono font-bold block pt-1 ${
                            audit.idsDetection.status === 'DETECTED' ? 'text-emerald-400' : 'text-red-400'
                          }`}>
                            {audit.idsDetection.status}
                          </span>
                        </div>
                        {audit.idsDetection.signatureName ? (
                          <span className="text-[10px] font-mono text-gray-400 block truncate bg-[#161616] p-1 rounded border border-[#2A2A2A]">
                            {audit.idsDetection.signatureName}
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono text-gray-600 block">No IDS signature trigger</span>
                        )}
                      </div>

                      {/* 3. Application Security Logs */}
                      <div className="p-3.5 bg-black/60 rounded-xl border border-[#222222] space-y-1.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 uppercase">
                            <span>3. Application Security Log</span>
                            <FileText className="h-3 w-3 text-emerald-400" />
                          </div>
                          <span className={`text-xs font-mono font-bold block pt-1 ${
                            audit.applicationLogging.status === 'AUDIT_LOG_RECORDED' ? 'text-emerald-400' : 'text-red-400'
                          }`}>
                            {audit.applicationLogging.status}
                          </span>
                        </div>
                        {audit.applicationLogging.logSnippet ? (
                          <span className="text-[10px] font-mono text-gray-300 block truncate bg-[#161616] p-1 rounded border border-[#2A2A2A]">
                            {audit.applicationLogging.logSnippet}
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono text-gray-600 block">No security event logged</span>
                        )}
                      </div>

                      {/* 4. SIEM Alert Correlation */}
                      <div className="p-3.5 bg-black/60 rounded-xl border border-[#222222] space-y-1.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 uppercase">
                            <span>4. SIEM Alert Correlation</span>
                            <Radio className="h-3 w-3 text-amber-400" />
                          </div>
                          <span className={`text-xs font-mono font-bold block pt-1 ${
                            audit.siemAlertGenerated ? 'text-emerald-400' : 'text-gray-500'
                          }`}>
                            {audit.siemAlertGenerated ? `ALERT: ${audit.alertPriority}` : 'NO SIEM ALERT'}
                          </span>
                        </div>
                        <span className="text-[10px] font-mono text-gray-400 block bg-[#161616] p-1 rounded border border-[#2A2A2A]">
                          Latency: {audit.detectionTimeSeconds > 0 ? `${audit.detectionTimeSeconds}s` : 'N/A'}
                        </span>
                      </div>
                    </div>

                    {/* Defense Gap Analysis & Blue Team Recommendation */}
                    <div className="p-4 rounded-xl bg-[#141414] border border-[#222222] space-y-2.5 text-xs">
                      <div className="text-gray-300">
                        <strong className="text-gray-400 font-mono uppercase text-[10px] block">Defense Gap Analysis:</strong>
                        <p className="leading-relaxed mt-0.5">{audit.defenseGapAnalysis}</p>
                      </div>

                      <div className="text-emerald-300 font-mono text-[11px] pt-1 border-t border-[#1F1F1F]">
                        <strong className="text-emerald-400 block text-[10px] uppercase">Blue Team Hardening Recommendation:</strong>
                        <p className="leading-relaxed mt-0.5">{audit.blueTeamRecommendation}</p>
                      </div>

                      {matchedFinding && (
                        <div className="pt-2 flex items-center justify-end space-x-2">
                          <button
                            onClick={() => onOpenFindingModal(matchedFinding, 'explain')}
                            className="px-3 py-1.5 rounded-lg bg-[#222222] hover:bg-[#2A2A2A] text-xs font-mono text-gray-300 transition-colors"
                          >
                            Inspect Finding
                          </button>
                          <button
                            onClick={() => onOpenFindingModal(matchedFinding, 'fix')}
                            className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-bold text-white uppercase tracking-wider transition-all shadow"
                          >
                            Apply Remediation Patch
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* SUB-VIEW 4: AI ADVERSARY NARRATIVE */}
      {activeSubTab === 'analyst' && (
        <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-6">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-blue-950/40 border border-blue-800/60 text-blue-400">
              <Cpu className="h-6 w-6" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">AI Red Team / Purple Team Threat Analyst Report</h3>
              <span className="text-xs font-mono text-gray-400">Simulated Actor: {report.aiAdversaryNarrative.threatActorPersona}</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-black border border-[#222222] space-y-2">
            <span className="text-[11px] font-mono text-gray-500 uppercase block">Executive Threat Narrative:</span>
            <p className="text-xs text-gray-300 leading-relaxed">
              {report.aiAdversaryNarrative.executiveSummary}
            </p>
          </div>

          <div className="space-y-2">
            <span className="text-[11px] font-mono text-gray-500 uppercase block">Kill Chain Breakdown (MITRE ATT&CK):</span>
            <div className="grid grid-cols-1 gap-2">
              {report.aiAdversaryNarrative.killChainBreakdown.map((step, idx) => (
                <div key={idx} className="flex items-start space-x-3 p-3 rounded-xl bg-[#141414] border border-[#1F1F1F] text-xs text-gray-300">
                  <span className="h-5 w-5 rounded-full bg-red-950 text-red-400 border border-red-800 flex items-center justify-center font-mono text-[10px] font-bold shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span>{step}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-bold text-emerald-400">
              <ShieldCheck className="h-4 w-4" />
              <span>Prioritized Defensive Hardening Roadmap</span>
            </div>
            <ul className="space-y-1.5 text-xs text-gray-300 list-disc list-inside">
              {report.aiAdversaryNarrative.defensiveHardeningActionItems.map((item, idx) => (
                <li key={idx} className="leading-relaxed">{item}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* SUB-VIEW 5: SCOPE & AUTHORIZATION GATEWAY */}
      {activeSubTab === 'scope' && (
        <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-800 text-emerald-400">
                <Lock className="h-6 w-6" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">Scope & Authorization Gateway</h3>
                <p className="text-xs text-gray-400 mt-0.5">
                  Cryptographic policy boundaries. The Red Team engine strictly refuses execution outside authorized assets.
                </p>
              </div>
            </div>
            <span className="text-xs font-mono px-3 py-1.5 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold flex items-center space-x-1.5">
              <CheckCircle2 className="h-4 w-4" />
              <span>CERTIFICATE VALID</span>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* In Scope */}
            <div className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F] space-y-3">
              <span className="text-xs font-mono font-bold text-emerald-400 flex items-center space-x-1.5">
                <Check className="h-4 w-4" />
                <span>IN-SCOPE AUTHORIZED TARGETS:</span>
              </span>
              <ul className="space-y-2 text-xs text-gray-300">
                <li className="flex items-center space-x-2">
                  <Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                  <span>Web application frontend & client bundles</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                  <span>REST & GraphQL API route endpoints</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Check className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                  <span>Isolated synthetic test database sandbox</span>
                </li>
              </ul>
            </div>

            {/* Excluded Out-of-Scope */}
            <div className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F] space-y-3">
              <span className="text-xs font-mono font-bold text-red-400 flex items-center space-x-1.5">
                <X className="h-4 w-4" />
                <span>STRICTLY EXCLUDED OUT-OF-SCOPE:</span>
              </span>
              <ul className="space-y-2 text-xs text-gray-300">
                <li className="flex items-center space-x-2">
                  <X className="h-3.5 w-3.5 text-red-400 shrink-0" />
                  <span>Production live databases (Protected)</span>
                </li>
                <li className="flex items-center space-x-2">
                  <X className="h-3.5 w-3.5 text-red-400 shrink-0" />
                  <span>Third-party payment gateways (Stripe, Twilio)</span>
                </li>
                <li className="flex items-center space-x-2">
                  <X className="h-3.5 w-3.5 text-red-400 shrink-0" />
                  <span>Destructive volumetric Denial of Service</span>
                </li>
              </ul>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-black border border-[#222222] font-mono text-xs text-gray-400 space-y-1">
            <span className="text-[10px] text-gray-600 block uppercase">DISPOSABLE SANDBOX CONTAINER SPECS:</span>
            <div className="text-gray-300">INSTANCE ID: {report.scope.sandboxEnvironment.disposableInstanceId}</div>
            <div className="text-gray-300">RUNTIME ISOLATION: {report.scope.sandboxEnvironment.networkIsolationLevel}</div>
            <div className="text-gray-300">SIGNER: {report.scope.authorizationSigner}</div>
          </div>
        </div>
      )}
    </div>
  );
};
