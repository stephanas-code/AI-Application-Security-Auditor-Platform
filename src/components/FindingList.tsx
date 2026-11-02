import React, { useState } from 'react';
import {
  VulnerabilityFinding,
  VulnerabilityCategory,
  Severity
} from '../types';
import {
  CheckCircle2,
  Code2,
  KeyRound,
  Boxes,
  Wrench,
  Search,
  ShieldCheck,
  Sparkles,
  Eye,
  Radar
} from 'lucide-react';
import { getFindingClarityDetails } from '../utils/findingClarity';

interface FindingListProps {
  findings: VulnerabilityFinding[];
  selectedFinding: VulnerabilityFinding | null;
  onSelectFinding: (finding: VulnerabilityFinding, initialTab?: 'explain' | 'recommend' | 'fix') => void;
  onQuickVerify: (finding: VulnerabilityFinding) => void;
}

export const FindingList: React.FC<FindingListProps> = ({
  findings,
  selectedFinding,
  onSelectFinding
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<'ALL' | 'ACTIVE' | 'RESOLVED'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const categories: { id: string; label: string; icon: any }[] = [
    { id: 'ALL', label: 'All Findings', icon: Boxes },
    { id: 'SAST', label: 'SAST (Code)', icon: Code2 },
    { id: 'SCA', label: 'Dependencies', icon: Boxes },
    { id: 'SECRETS', label: 'Secrets & Keys', icon: KeyRound },
    { id: 'CONFIG', label: 'Infra & Config', icon: Wrench },
  ];

  const filteredFindings = findings.filter(f => {
    if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;
    if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
    if (selectedStatus === 'ACTIVE' && (f.status === 'VERIFIED_RESOLVED' || f.status === 'FALSE_POSITIVE')) return false;
    if (selectedStatus === 'RESOLVED' && f.status !== 'VERIFIED_RESOLVED') return false;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchFile = f.file.toLowerCase().includes(q);
      const matchCwe = f.cwe.toLowerCase().includes(q);
      const matchDesc = f.description.toLowerCase().includes(q);
      if (!matchTitle && !matchFile && !matchCwe && !matchDesc) return false;
    }

    return true;
  });

  const getSeverityPill = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-red-950/40 text-[#FF3B30] border border-red-900/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-orange-950/40 text-orange-400 border border-orange-900/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-amber-950/40 text-amber-400 border border-amber-900/40">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-blue-950/40 text-blue-400 border border-blue-900/40">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-[#1A1A1A] text-gray-400 border border-[#333333]">INFO</span>;
    }
  };

  const getCategoryPill = (cat: VulnerabilityCategory) => {
    switch (cat) {
      case 'SAST':
        return <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-[#1A1A1A] text-gray-300 border border-[#333333]">SAST</span>;
      case 'SCA':
        return <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-[#1A1A1A] text-purple-300 border border-[#333333]">SCA DEP</span>;
      case 'SECRETS':
        return <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-[#1A1A1A] text-red-300 border border-[#333333]">SECRET</span>;
      case 'CONFIG':
        return <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-[#1A1A1A] text-teal-300 border border-[#333333]">CONFIG</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-[#1A1A1A] text-gray-300">DAST</span>;
    }
  };

  return (
    <div className="bg-[#111111] rounded-2xl border border-[#1F1F1F] overflow-hidden shadow-xl space-y-0">

      {/* Category Bar & Controls */}
      <div className="p-4 border-b border-[#1F1F1F] bg-[#161616] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">

          {/* Category Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            {categories.map((c) => {
              const Icon = c.icon;
              const count = c.id === 'ALL'
                ? findings.length
                : findings.filter(f => f.category === c.id).length;
              return (
                <button
                  key={c.id}
                  onClick={() => setSelectedCategory(c.id)}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold tracking-tight transition-all ${selectedCategory === c.id
                      ? 'bg-[#1A1A1A] text-white border border-[#333333] shadow-sm'
                      : 'bg-[#0D0D0D] text-gray-400 hover:text-white hover:bg-[#141414] border border-[#1F1F1F]'
                    }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{c.label}</span>
                  <span className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono ${selectedCategory === c.id ? 'bg-[#333333] text-white' : 'bg-[#1F1F1F] text-gray-400'
                    }`}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Status Filter (Active vs Resolved) */}
          <div className="flex items-center bg-[#0D0D0D] p-1 rounded-lg border border-[#1F1F1F] text-xs">
            <button
              onClick={() => setSelectedStatus('ALL')}
              className={`px-2.5 py-1 rounded-md font-semibold tracking-tight transition-all ${selectedStatus === 'ALL' ? 'bg-[#1A1A1A] text-white border border-[#333333]' : 'text-gray-500 hover:text-white'
                }`}
            >
              All ({findings.length})
            </button>
            <button
              onClick={() => setSelectedStatus('ACTIVE')}
              className={`px-2.5 py-1 rounded-md font-semibold tracking-tight transition-all ${selectedStatus === 'ACTIVE' ? 'bg-red-950/40 text-[#FF3B30] border border-red-900/60' : 'text-gray-500 hover:text-white'
                }`}
            >
              Active ({findings.filter(f => f.status !== 'VERIFIED_RESOLVED').length})
            </button>
            <button
              onClick={() => setSelectedStatus('RESOLVED')}
              className={`px-2.5 py-1 rounded-md font-semibold tracking-tight transition-all ${selectedStatus === 'RESOLVED' ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-900/60' : 'text-gray-500 hover:text-white'
                }`}
            >
              Verified Clean ({findings.filter(f => f.status === 'VERIFIED_RESOLVED').length})
            </button>
          </div>
        </div>

        {/* Search & Severity Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="h-3.5 w-3.5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings by vulnerability, CWE, file, or pattern..."
              className="w-full pl-8 pr-3 py-1.5 bg-[#0D0D0D] border border-[#1F1F1F] rounded-lg text-xs text-white placeholder-gray-500 focus:outline-none focus:border-[#333333]"
            />
          </div>

          <div className="flex items-center space-x-1.5 text-xs text-gray-400 font-mono">
            <span className="font-semibold uppercase tracking-wider text-[10px]">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-[#0D0D0D] border border-[#1F1F1F] rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-[#333333]"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Only</option>
              <option value="MEDIUM">Medium Only</option>
              <option value="LOW">Low / Info</option>
            </select>
          </div>
        </div>
      </div>

      {/* Priority Findings Cards */}
      <div className="p-4 space-y-4 bg-[#0A0A0A]">
        {filteredFindings.map((finding) => {
          const isSelected = selectedFinding?.id === finding.id;
          const isResolved = finding.status === 'VERIFIED_RESOLVED';
          const clarity = getFindingClarityDetails(finding);

          const borderAccent = isResolved
            ? 'border-l-4 border-l-emerald-500'
            : finding.severity === 'CRITICAL'
              ? 'border-l-4 border-l-[#FF3B30]'
              : finding.severity === 'HIGH'
                ? 'border-l-4 border-l-orange-500'
                : 'border-l-4 border-l-blue-500';

          return (
            <div
              key={finding.id}
              className={`p-5 rounded-xl transition-all border border-[#1F1F1F] ${borderAccent} ${isSelected ? 'bg-[#181818]' : 'bg-[#111111] hover:bg-[#141414]'
                } ${isResolved ? 'opacity-85' : ''}`}
            >
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">

                {/* Finding Info */}
                <div className="space-y-3 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    {getSeverityPill(finding.severity)}
                    {getCategoryPill(finding.category)}

                    <span className="text-[10px] font-mono text-blue-300 bg-blue-950/40 px-2 py-0.5 rounded border border-blue-900/40 font-semibold">
                      {clarity.vulnerabilityTypeLabel}
                    </span>

                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[#1A1A1A] text-gray-300 border border-[#333333]">
                      CVSS {finding.cvssScore}
                    </span>

                    <span className="text-[9px] font-mono text-emerald-400 bg-[#141414] px-1.5 py-0.5 rounded border border-[#1F1F1F]">
                      {finding.confidence}% CONFIDENCE
                    </span>

                    {isResolved && (
                      <span className="flex items-center space-x-1 text-[9px] font-bold font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded-full border border-emerald-900">
                        <CheckCircle2 className="h-3 w-3" />
                        <span>VERIFIED CLEAN</span>
                      </span>
                    )}
                  </div>

                  <h3
                    onClick={() => onSelectFinding(finding)}
                    className="text-base font-bold text-white hover:text-blue-400 cursor-pointer transition-colors"
                  >
                    {finding.title}
                  </h3>

                  {/* Clear 4-Part Breakdown Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    {/* 1. What & Why */}
                    <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#1C1C1C] space-y-1">
                      <div className="text-[10px] font-mono font-bold uppercase text-red-400 flex items-center gap-1.5">
                        <span>1. Vulnerability Type & Risk</span>
                      </div>
                      <p className="text-xs text-gray-300 leading-relaxed">
                        {clarity.plainSummary}
                      </p>
                    </div>

                    {/* 2. How Detected */}
                    <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#1C1C1C] space-y-1">
                      <div className="text-[10px] font-mono font-bold uppercase text-cyan-400 flex items-center gap-1.5">
                        <Radar className="h-3 w-3" />
                        <span>2. How It Was Detected ({clarity.detectionEngine})</span>
                      </div>
                      <p className="text-xs text-gray-300 leading-relaxed">
                        {clarity.detectionExplanation}
                      </p>
                    </div>

                    {/* 3. How to Safely Verify */}
                    <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#1C1C1C] space-y-1">
                      <div className="text-[10px] font-mono font-bold uppercase text-amber-400 flex items-center gap-1.5">
                        <Eye className="h-3 w-3" />
                        <span>3. Safe Verification ({clarity.verificationEnvironment})</span>
                      </div>
                      <ol className="text-xs text-gray-300 space-y-1 list-decimal list-inside leading-relaxed">
                        {clarity.safeVerificationSteps.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ol>
                    </div>

                    {/* 4. Recommended Patch */}
                    <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#1C1C1C] space-y-1">
                      <div className="text-[10px] font-mono font-bold uppercase text-emerald-400 flex items-center gap-1.5">
                        <Wrench className="h-3 w-3" />
                        <span>4. Recommended Patch & Fix</span>
                      </div>
                      <p className="text-xs text-gray-300 leading-relaxed">
                        {finding.recommendation}
                      </p>
                      {finding.proposedPatch && (
                        <p className="text-[11px] font-mono text-emerald-400 pt-1">
                          ✓ Automated patch ready for {finding.proposedPatch.fileModified}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono text-gray-400">
                    <span className="text-gray-300 bg-[#161616] px-2 py-0.5 rounded border border-[#222]">
                      📍 File: {finding.file} (Line {finding.line})
                    </span>
                    {finding.dependencyInfo && (
                      <span className="text-purple-300 bg-purple-950/30 px-2 py-0.5 rounded border border-purple-900/40">
                        📦 Upgrade: {finding.dependencyInfo.packageName} {finding.dependencyInfo.currentVersion} → {finding.dependencyInfo.fixedVersion}
                      </span>
                    )}
                  </div>
                </div>

                {/* Right Column: Code Sink + Actions */}
                <div className="flex flex-col justify-between gap-3 lg:w-72 shrink-0">
                  <div className="w-full bg-black p-3 rounded-lg border border-[#1F1F1F] font-mono text-[10px] text-gray-300 overflow-hidden">
                    <div className="text-[9px] text-gray-500 mb-1 flex items-center justify-between uppercase font-bold">
                      <span>Detected Code / Config Sink</span>
                      <span className="text-[#FF3B30]">Line {finding.line}</span>
                    </div>
                    <div className="truncate text-red-400">
                      {finding.codeSnippet}
                    </div>
                  </div>

                  {/* 3-Stage Action Group */}
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => onSelectFinding(finding, 'explain')}
                      className="flex-1 px-3 py-2 rounded-lg bg-[#1A1A1A] hover:bg-[#222222] border border-[#333333] text-blue-400 hover:text-blue-300 text-[10px] font-bold uppercase tracking-tight transition-colors cursor-pointer"
                    >
                      Full Breakdown
                    </button>

                    <button
                      onClick={() => onSelectFinding(finding, 'recommend')}
                      className="flex-1 px-3 py-2 rounded-lg bg-[#1A1A1A] hover:bg-[#222222] border border-[#333333] text-gray-300 hover:text-white text-[10px] font-bold uppercase tracking-tight transition-colors cursor-pointer"
                    >
                      Verify & Guide
                    </button>

                    {isResolved ? (
                      <button
                        onClick={() => onSelectFinding(finding, 'fix')}
                        className="w-full flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-emerald-950/60 text-emerald-400 border border-emerald-900 text-[10px] font-bold uppercase tracking-tight transition-colors cursor-pointer"
                      >
                        <ShieldCheck className="h-3.5 w-3.5" />
                        <span>View Verification Proof</span>
                      </button>
                    ) : (
                      <button
                        onClick={() => onSelectFinding(finding, 'fix')}
                        className="w-full flex items-center justify-center space-x-1.5 px-3.5 py-2 rounded-lg bg-[#FF3B30] hover:bg-[#D32F2F] text-black text-[10px] font-black uppercase tracking-tight transition-all shadow-sm cursor-pointer"
                      >
                        <Sparkles className="h-3.5 w-3.5 text-black" />
                        <span>View Patch & Fix Vulnerability</span>
                      </button>
                    )}
                  </div>
                </div>

              </div>
            </div>
          );
        })}

        {filteredFindings.length === 0 && (
          <div className="p-12 text-center text-gray-500 space-y-2 bg-[#111111] rounded-xl border border-[#1F1F1F]">
            <ShieldCheck className="h-10 w-10 text-emerald-500 mx-auto opacity-70" />
            <h4 className="text-sm font-semibold text-gray-300">No matching vulnerabilities found</h4>
            <p className="text-xs text-gray-600">All filters are clean or no findings match the query.</p>
          </div>
        )}
      </div>

    </div>
  );
};
