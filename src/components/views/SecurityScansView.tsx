import React, { useState } from 'react';
import { 
  VulnerabilityFinding, 
  ScanResult, 
  ScanTarget, 
  FindingCategory, 
  SeverityLevel 
} from '../../types';
import { FindingList } from '../FindingList';
import { CodebaseViewer } from '../CodebaseViewer';
import { DASTProbeSimulator } from '../DASTProbeSimulator';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Smartphone, 
  Monitor, 
  FileCode, 
  Key, 
  Package, 
  Server, 
  CheckCircle2, 
  AlertTriangle,
  Zap,
  Play,
  Terminal
} from 'lucide-react';

interface SecurityScansViewProps {
  scanResult: ScanResult;
  target: ScanTarget;
  selectedFinding: VulnerabilityFinding | null;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  onOpenRemediation: (finding: VulnerabilityFinding) => void;
}

export const SecurityScansView: React.FC<SecurityScansViewProps> = ({
  scanResult,
  target,
  selectedFinding,
  onSelectFinding,
  onOpenRemediation
}) => {
  const [categoryFilter, setCategoryFilter] = useState<FindingCategory | 'ALL'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeInspectorTab, setActiveInspectorTab] = useState<'code' | 'dast' | 'details'>('code');

  const categories: Array<{ id: FindingCategory | 'ALL'; label: string; icon: any }> = [
    { id: 'ALL', label: 'All Categories', icon: Filter },
    { id: 'SAST', label: 'Static Code (SAST)', icon: FileCode },
    { id: 'SECRETS', label: 'Secrets & Keys', icon: Key },
    { id: 'SCA', label: 'Dependencies (SCA)', icon: Package },
    { id: 'CONFIG', label: 'Config & Infra', icon: Server },
    { id: 'MOBILE_STATIC', label: 'Mobile (APK/IPA)', icon: Smartphone },
    { id: 'BINARY_STATIC', label: 'Binary (EXE/DMG)', icon: Monitor }
  ];

  const filteredFindings = scanResult.findings.filter(f => {
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.cwe.toLowerCase().includes(q) ||
        f.file.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const activeFinding = selectedFinding || filteredFindings[0] || null;

  return (
    <div className="space-y-5 pb-12">
      {/* Header & Filter Controls */}
      <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <ShieldAlert className="h-5 w-5 text-blue-400" />
              <h1 className="text-base font-black text-white uppercase tracking-wider">Security Vulnerability Scanner</h1>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Multi-engine inspection across SAST, Secrets, SCA, Cloud Config, and Mobile/Desktop Binary signatures.
            </p>
          </div>

          {/* Search Bar */}
          <div className="relative min-w-[260px]">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings, CWE, files..."
              className="w-full pl-9 pr-3 py-2 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50"
            />
          </div>
        </div>

        {/* Categories Bar */}
        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1">
          {categories.map((cat) => {
            const Icon = cat.icon;
            const count = cat.id === 'ALL' 
              ? scanResult.findings.length 
              : scanResult.findings.filter(f => f.category === cat.id).length;
            const isActive = categoryFilter === cat.id;

            return (
              <button
                key={cat.id}
                onClick={() => setCategoryFilter(cat.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white shadow'
                    : 'bg-[#161616] text-gray-400 hover:text-white border border-[#1F1F1F]'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{cat.label}</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${isActive ? 'bg-blue-800 text-white' : 'bg-[#222222] text-gray-400'}`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Severity Selector */}
        <div className="flex items-center space-x-2 pt-2 border-t border-[#1A1A1A] text-xs font-mono">
          <span className="text-gray-500 text-[11px] uppercase tracking-wider font-bold">Severity:</span>
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition-all ${
                severityFilter === sev
                  ? sev === 'CRITICAL' ? 'bg-red-600 text-white' :
                    sev === 'HIGH' ? 'bg-orange-600 text-white' :
                    sev === 'MEDIUM' ? 'bg-amber-600 text-black' :
                    'bg-blue-600 text-white'
                  : 'bg-[#161616] text-gray-400 hover:text-white border border-[#1F1F1F]'
              }`}
            >
              {sev}
            </button>
          ))}
          <span className="text-gray-500 ml-auto text-[11px]">
            Showing {filteredFindings.length} of {scanResult.findings.length} findings
          </span>
        </div>
      </div>

      {/* Main 2-Column Finding Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Finding Cards List (5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3 bg-[#111111] border border-[#1F1F1F] rounded-xl flex items-center justify-between text-xs font-mono text-gray-400">
            <span>Finding Records</span>
            <span>{filteredFindings.length} Filtered</span>
          </div>

          <div className="space-y-2.5 max-h-[750px] overflow-y-auto pr-1">
            {filteredFindings.map((finding) => {
              const isSelected = activeFinding?.id === finding.id;
              const isResolved = finding.status === 'VERIFIED_RESOLVED';

              return (
                <div
                  key={finding.id}
                  onClick={() => onSelectFinding(finding)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-[#181818] border-blue-500/80 shadow-lg'
                      : isResolved
                      ? 'bg-[#101914] border-emerald-900/40 hover:border-emerald-700/60 opacity-80'
                      : 'bg-[#141414] border-[#1F1F1F] hover:border-[#333333] hover:bg-[#161616]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center space-x-2">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                          isResolved ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                          finding.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                          finding.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                          'bg-amber-950 text-amber-400 border border-amber-800'
                        }`}>
                          {isResolved ? 'RESOLVED' : finding.severity}
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-[#1C1C1C] text-gray-400 font-mono text-[9px] border border-[#2A2A2A]">
                          {finding.cwe}
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-blue-950/60 text-blue-400 font-mono text-[9px] border border-blue-900/50 uppercase">
                          {finding.category}
                        </span>
                      </div>
                      <h4 className="text-xs font-bold text-white truncate">{finding.title}</h4>
                      <p className="text-[11px] font-mono text-gray-500 truncate">{finding.file}:{finding.line}</p>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-[10px] font-mono font-bold text-gray-400 block">CVSS {finding.cvssScore}</span>
                      {finding.proposedPatch && !isResolved && (
                        <span className="inline-flex items-center space-x-1 text-[10px] font-mono text-blue-400 mt-1">
                          <Zap className="h-3 w-3" />
                          <span>Patch Ready</span>
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}

            {filteredFindings.length === 0 && (
              <div className="p-8 text-center bg-[#111111] border border-[#1F1F1F] rounded-2xl text-xs text-gray-500 font-mono">
                No vulnerabilities match the current filter selection.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Deep Inspection Panel (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          {activeFinding ? (
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-5">
              {/* Finding Title & Top Actions */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-[#1F1F1F]">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                      activeFinding.status === 'VERIFIED_RESOLVED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                      activeFinding.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                      'bg-orange-950 text-orange-400 border border-orange-800'
                    }`}>
                      {activeFinding.status === 'VERIFIED_RESOLVED' ? 'VERIFIED RESOLVED' : activeFinding.severity}
                    </span>
                    <span className="text-xs font-mono text-gray-400">{activeFinding.cwe} ({activeFinding.cweName})</span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1.5">{activeFinding.title}</h2>
                  <p className="text-xs font-mono text-gray-500 mt-0.5">{activeFinding.file} (Line {activeFinding.line})</p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  {activeFinding.proposedPatch && (
                    <button
                      onClick={() => onOpenRemediation(activeFinding)}
                      className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow"
                    >
                      <Zap className="h-3.5 w-3.5" />
                      <span>Remediate in Hub</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Inspector View Mode Tabs */}
              <div className="flex items-center space-x-2 border-b border-[#1F1F1F] pb-2">
                <button
                  onClick={() => setActiveInspectorTab('code')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    activeInspectorTab === 'code'
                      ? 'bg-[#222222] text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Codebase & Highlight
                </button>
                <button
                  onClick={() => setActiveInspectorTab('details')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    activeInspectorTab === 'details'
                      ? 'bg-[#222222] text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Root Cause & Attack Vector
                </button>
                {activeFinding.testCase && (
                  <button
                    onClick={() => setActiveInspectorTab('dast')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5 ${
                      activeInspectorTab === 'dast'
                        ? 'bg-[#222222] text-white'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    <Play className="h-3 w-3 text-emerald-400" />
                    <span>Dynamic DAST Probe</span>
                  </button>
                )}
              </div>

              {/* Tab 1: Code View */}
              {activeInspectorTab === 'code' && (
                <div className="space-y-4">
                  <CodebaseViewer
                    target={target}
                    findings={scanResult.findings}
                    activeFinding={activeFinding}
                    onOpenFinding={(f) => onOpenRemediation(f)}
                  />
                  <div className="p-3.5 rounded-xl bg-[#161616] border border-[#1F1F1F] text-xs text-gray-400">
                    <span className="font-bold text-white block mb-1">Security Impact:</span>
                    {activeFinding.businessImpact || activeFinding.description}
                  </div>
                </div>
              )}

              {/* Tab 2: Detailed Root Cause Analysis */}
              {activeInspectorTab === 'details' && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-[#161616] border border-[#1F1F1F] space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-blue-400 font-bold">Root Cause Mechanism</span>
                    <p className="text-xs text-gray-300 leading-relaxed">{activeFinding.rootCause}</p>
                  </div>

                  <div className="p-4 rounded-xl bg-[#161616] border border-red-900/30 space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-red-400 font-bold">Attack Scenario & Exploit Vector</span>
                    <p className="text-xs text-gray-300 leading-relaxed">{activeFinding.attackScenario}</p>
                  </div>

                  <div className="p-4 rounded-xl bg-[#161616] border border-[#1F1F1F] space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold">Engineering Recommendation</span>
                    <p className="text-xs text-gray-300 leading-relaxed">{activeFinding.recommendation}</p>
                  </div>
                </div>
              )}

              {/* Tab 3: DAST Probe Simulator */}
              {activeInspectorTab === 'dast' && activeFinding.testCase && (
                <div className="space-y-4">
                  <DASTProbeSimulator
                    finding={activeFinding}
                    testCase={activeFinding.testCase}
                  />
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center bg-[#111111] border border-[#1F1F1F] rounded-2xl text-xs text-gray-500 font-mono">
              Select a finding from the left panel to inspect code context and exploit analysis.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
