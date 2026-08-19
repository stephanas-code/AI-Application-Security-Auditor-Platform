import React, { useState } from 'react';
import { 
  Sparkles, 
  GitMerge, 
  Flame, 
  AlertOctagon, 
  Compass,
  ArrowUpRight
} from 'lucide-react';
import { AIAnalystInsight, VulnerabilityFinding } from '../types';

interface AIAnalystPanelProps {
  insight: AIAnalystInsight | undefined;
  findings: VulnerabilityFinding[];
  onSelectFinding: (finding: VulnerabilityFinding) => void;
}

export const AIAnalystPanel: React.FC<AIAnalystPanelProps> = ({
  insight,
  findings,
  onSelectFinding
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'chains' | 'roadmap'>('overview');

  if (!insight) return null;

  return (
    <div className="bg-[#111111] rounded-2xl border border-[#1F1F1F] overflow-hidden shadow-xl">
      {/* Panel Header */}
      <div className="px-6 py-4 bg-[#161616] border-b border-[#1F1F1F] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse"></div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-xs font-bold uppercase tracking-widest text-white">AI Security Analyst</h2>
              <span className="px-2 py-0.5 text-[9px] font-mono bg-[#1A1A1A] text-blue-400 border border-[#333333] rounded">
                GEMINI 3.7 REASONING
              </span>
            </div>
            <p className="text-[11px] text-gray-500">Risk correlation, multi-step exploit analysis & remediation triage</p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-[#0D0D0D] p-1 rounded-lg border border-[#1F1F1F] text-xs">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-md font-semibold tracking-tight transition-all ${
              activeTab === 'overview'
                ? 'bg-[#1A1A1A] text-white border border-[#333333]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Executive Triage
          </button>
          <button
            onClick={() => setActiveTab('chains')}
            className={`px-3 py-1.5 rounded-md font-semibold tracking-tight transition-all flex items-center space-x-1.5 ${
              activeTab === 'chains'
                ? 'bg-[#1A1A1A] text-white border border-[#333333]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <span>Attack Chains</span>
            {insight.attackChains.length > 0 && (
              <span className="h-4 w-4 rounded-full bg-red-900/40 text-[#FF3B30] text-[10px] flex items-center justify-center font-bold">
                {insight.attackChains.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('roadmap')}
            className={`px-3 py-1.5 rounded-md font-semibold tracking-tight transition-all ${
              activeTab === 'roadmap'
                ? 'bg-[#1A1A1A] text-white border border-[#333333]'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Remediation Roadmap
          </button>
        </div>
      </div>

      {/* Panel Body */}
      <div className="p-6">
        {activeTab === 'overview' && (
          <div className="space-y-5">
            {/* Elegant Italic Insight Box */}
            <div className="p-5 rounded-xl bg-[#141414] border border-[#1F1F1F] relative">
              <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <Compass className="h-3.5 w-3.5 text-blue-400" />
                <span>Analysis Insight</span>
              </h4>
              <p className="text-sm font-serif italic text-blue-100 leading-relaxed">
                "{insight.executiveTakeaway}"
              </p>
            </div>

            {/* Blast Radius & Immediate Attention Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Blast Radius */}
              <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#1F1F1F]">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Flame className="h-4 w-4 text-[#FF3B30]" />
                    <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">Blast Radius Assessment</h4>
                  </div>
                  <span className="text-xs font-mono font-bold text-[#FF3B30]">
                    {insight.blastRadiusScore} / 100
                  </span>
                </div>
                <div className="w-full bg-[#1F1F1F] h-1 rounded-full mb-3 overflow-hidden">
                  <div 
                    className="bg-[#FF3B30] h-full rounded-full"
                    style={{ width: `${insight.blastRadiusScore}%` }}
                  />
                </div>
                <p className="text-xs text-gray-400 leading-relaxed">
                  {insight.blastRadiusSummary}
                </p>
              </div>

              {/* Immediate Attention List */}
              <div className="p-4 rounded-xl bg-[#0F0F0F] border border-[#1F1F1F]">
                <div className="flex items-center space-x-2 mb-2">
                  <AlertOctagon className="h-4 w-4 text-orange-500" />
                  <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">Requires Immediate Attention</h4>
                </div>
                <div className="space-y-2">
                  {insight.immediatePriorities.map((item, idx) => (
                    <div key={idx} className="flex items-center justify-between text-xs p-2 rounded bg-[#141414] border border-[#1F1F1F] text-gray-300">
                      <span className="truncate pr-2 font-mono text-[11px] text-red-300">
                        {item}
                      </span>
                      <span className="px-1.5 py-0.5 text-[9px] bg-red-950/40 text-red-400 font-bold font-mono rounded border border-red-900/60 flex-shrink-0">
                        P0
                      </span>
                    </div>
                  ))}
                  {insight.immediatePriorities.length === 0 && (
                    <div className="text-xs text-emerald-400 flex items-center space-x-1.5 py-2 font-mono">
                      <span>✓ ZERO IMMEDIATE CRITICAL BLOCKERS</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'chains' && (
          <div className="space-y-4">
            <div className="text-xs text-gray-500">
              The AI Security Analyst correlated the following multi-step exploit chains where separate findings can be combined by an adversary:
            </div>

            {insight.attackChains.map((chain) => (
              <div key={chain.id} className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F] border-l-4 border-l-[#FF3B30] space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <GitMerge className="h-4 w-4 text-[#FF3B30]" />
                    <h4 className="text-sm font-bold text-white">{chain.title}</h4>
                  </div>
                  <span className="px-2 py-0.5 text-[9px] font-bold font-mono rounded bg-red-950/40 text-red-400 border border-red-900/40 uppercase">
                    Critical Chain
                  </span>
                </div>

                <p className="text-xs text-gray-300 leading-relaxed bg-[#0D0D0D] p-3 rounded-lg border border-[#1F1F1F]">
                  <span className="font-semibold text-red-400">Exploit Narrative: </span>
                  {chain.narrative}
                </p>

                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <span className="text-[11px] text-gray-500 font-medium">Involved Findings:</span>
                  {chain.findingsInvolved.map((fid) => {
                    const findingObj = findings.find(f => f.id === fid);
                    return findingObj ? (
                      <button
                        key={fid}
                        onClick={() => onSelectFinding(findingObj)}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-[#1A1A1A] hover:bg-[#222222] text-blue-400 text-[11px] font-mono border border-[#333333] transition-colors"
                      >
                        <span>{findingObj.title.substring(0, 32)}...</span>
                        <ArrowUpRight className="h-3 w-3" />
                      </button>
                    ) : null;
                  })}
                </div>
              </div>
            ))}

            {insight.attackChains.length === 0 && (
              <div className="p-6 text-center text-xs text-gray-500 bg-[#0F0F0F] rounded-xl border border-[#1F1F1F]">
                No complex multi-step attack correlation chains detected.
              </div>
            )}
          </div>
        )}

        {activeTab === 'roadmap' && (
          <div className="space-y-4">
            <div className="text-xs text-gray-500">
              Prioritized step-by-step remediation plan structured to maximize security score with minimal developer friction:
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {insight.remediationRoadmap.map((phase, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F] flex flex-col justify-between">
                  <div>
                    <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-[#1A1A1A] text-blue-400 border border-[#333333] rounded">
                      STEP {idx + 1}
                    </span>
                    <h4 className="text-xs font-bold text-white mt-2 mb-3">
                      {phase.phase}
                    </h4>
                    <ul className="space-y-2 text-xs text-gray-400">
                      {phase.actions.map((act, aIdx) => (
                        <li key={aIdx} className="flex items-start space-x-1.5">
                          <span className="text-blue-500 font-bold">•</span>
                          <span className="leading-snug text-gray-300">{act}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="mt-4 pt-3 border-t border-[#1F1F1F] text-[10px] text-gray-500 font-mono">
                    EST. EFFORT: <span className="text-emerald-400 font-semibold">{phase.estimatedEffort}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
